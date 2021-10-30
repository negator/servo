/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! A thread that takes a URL and streams back the binary data.

#![allow(unsafe_code)]

use crate::connector::{
    create_http_client, create_tls_config, ConnectionCerts, ExtraCerts, ALPN_H2_H1,
};
use crate::cookie;
use crate::cookie_storage::CookieStorage;
use crate::fetch::cors_cache::CorsCache;
use crate::fetch::methods::{fetch, CancellationListener, FetchContext};
use crate::filemanager_thread::FileManager;
use crate::hsts::HstsList;
use crate::http_cache::HttpCache;
use crate::http_loader::{http_redirect_fetch, HttpState};
use crate::storage_thread::StorageThreadFactory;
use crate::websocket_loader::{self, HANDLE as WS_HANDLE};
use crossbeam_channel::Sender;
use devtools_traits::DevtoolsControlMsg;
use embedder_traits::resources::{self, Resource};
use embedder_traits::EmbedderProxy;
use futures_util::StreamExt;
use hyper_serde::Serde;
use ipc_channel::asynch::IpcStream;
use ipc_channel::ipc::{self, IpcReceiver, IpcSender};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use net_traits::blob_url_store::parse_blob_url;
use net_traits::filemanager_thread::FileTokenCheck;
use net_traits::request::{Destination, RequestBuilder};
use net_traits::response::{Response, ResponseInit};
use net_traits::storage_thread::StorageThreadMsg;
use net_traits::DiscardFetch;
use net_traits::FetchTaskTarget;
use net_traits::WebSocketNetworkEvent;
use net_traits::{CookieSource, CoreResourceMsg, CoreResourceThread};
use net_traits::{CustomResponseMediator, FetchChannels};
use net_traits::{ResourceFetchTiming, ResourceTimingType};
use net_traits::{ResourceThreads, WebSocketDomAction};
use profile_traits::mem::ProfilerChan as MemProfilerChan;
use profile_traits::mem::{Report, ReportKind, ReportsChan};
use profile_traits::time::ProfilerChan;
use serde::{Deserialize, Serialize};
use servo_arc::Arc as ServoArc;
use servo_url::{ImmutableOrigin, ServoUrl};
use std::borrow::{Cow, ToOwned};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufWriter;
use std::io::prelude::*;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use tokio_compat::runtime::Runtime;

/// Returns a tuple of (public, private) senders to the new threads.
pub fn new_resource_threads(
    runtime: &'static Runtime,
    user_agent: Cow<'static, str>,
    devtools_chan: Option<Sender<DevtoolsControlMsg>>,
    embedder_proxy: EmbedderProxy,
    config_dir: Option<PathBuf>,
    certificate_path: Option<String>,
) -> (ResourceThreads, ResourceThreads) {
    let (public_core, private_core) = new_core_resource_thread(
        runtime,
        user_agent,
        devtools_chan,
        embedder_proxy,
        config_dir.clone(),
        certificate_path,
    );
    let storage: IpcSender<StorageThreadMsg> = StorageThreadFactory::new(runtime, config_dir);
    (
        ResourceThreads::new(public_core, storage.clone()),
        ResourceThreads::new(private_core, storage),
    )
}

/// Create a CoreResourceThread
pub fn new_core_resource_thread(
    runtime: &'static Runtime,
    user_agent: Cow<'static, str>,
    devtools_chan: Option<Sender<DevtoolsControlMsg>>,
    embedder_proxy: EmbedderProxy,
    config_dir: Option<PathBuf>,
    certificate_path: Option<String>,
) -> (CoreResourceThread, CoreResourceThread) {
    let (public_setup_chan, public_setup_port) = ipc::channel().unwrap();
    let (private_setup_chan, private_setup_port) = ipc::channel().unwrap();

    runtime.spawn_std(async move {
        let resource_manager = CoreResourceManager::new(
            user_agent,
            devtools_chan,
            embedder_proxy,
            certificate_path.clone(),
        );

        let mut channel_manager = ResourceChannelManager {
            resource_manager,
            config_dir,
            certificate_path,
        };        
        
        channel_manager
            .start(
                runtime,                
                public_setup_port,
                private_setup_port,
            )
            .await
    });
    (public_setup_chan, private_setup_chan)
}

struct ResourceChannelManager {
    resource_manager: CoreResourceManager,
    config_dir: Option<PathBuf>,
    certificate_path: Option<String>,
}

fn create_http_states(
    runtime: &Runtime,
    config_dir: Option<&Path>,    
    certificate_path: Option<String>,
) -> Arc<HttpState> {
    let mut hsts_list = HstsList::from_servo_preload();
    let mut auth_cache = AuthCache::new();
    let http_cache = HttpCache::new();
    let mut external_cookies = vec![];
    if let Some(config_dir) = config_dir {
        read_json_from_file(&mut auth_cache, config_dir, "auth_cache.json");
        read_json_from_file(&mut hsts_list, config_dir, "hsts_list.json");
        read_json_from_file(&mut external_cookies, config_dir, "cookie_jar.json");
    }

    let mut cookie_jar = CookieStorage::new_from_external(150, external_cookies);

    let certs = match certificate_path {
        Some(ref path) => fs::read_to_string(path).expect("Couldn't not find certificate file"),
        None => resources::read_string(Resource::SSLCertificates),
    };

    let extra_certs = ExtraCerts::new();
    let connection_certs = ConnectionCerts::new();

    let http_state = HttpState {
        hsts_list: RwLock::new(hsts_list),
        cookie_jar: RwLock::new(cookie_jar),
        auth_cache: RwLock::new(auth_cache),
        history_states: RwLock::new(HashMap::new()),
        http_cache: RwLock::new(http_cache),
        http_cache_state: Mutex::new(HashMap::new()),
        client: create_http_client(
            create_tls_config(
                &certs,
                ALPN_H2_H1,
                extra_certs.clone(),
                connection_certs.clone(),
            ),
            runtime.executor(),
        ),
        extra_certs,
        connection_certs,
    };

    Arc::new(http_state)
}

impl ResourceChannelManager {
    #[allow(unsafe_code)]
    async fn start(
        &mut self,
        runtime: &'static Runtime,        
        public_receiver: IpcReceiver<CoreResourceMsg>,
        private_receiver: IpcReceiver<CoreResourceMsg>,
    ) {
        let public_http_state = create_http_states(
            runtime,        
            self.config_dir.as_ref().map(Deref::deref),
            self.certificate_path.clone(),
        );

        let mut stream =
            futures03::stream::select(public_receiver.to_stream(), private_receiver.to_stream());
        while let Ok(msg) = stream.select_next_some().await {
            self.process_msg(runtime, msg, &public_http_state).await;
        }
    }

    /// Returns false if the thread should exit.
    async fn process_msg(
        &mut self,
        runtime: &'static Runtime,
        msg: CoreResourceMsg,
        http_state: &Arc<HttpState>,
    ) -> bool {
        match msg {
            CoreResourceMsg::Fetch(req_init, channels) => match channels {
                FetchChannels::ResponseMsg(sender, cancel_chan) => {
                    self.resource_manager
                        .fetch(runtime, req_init, None, sender, http_state, cancel_chan)
                        .await;
                },
                FetchChannels::WebSocket {
                    event_sender,
                    action_receiver,
                } => self.resource_manager.websocket_connect(
                    req_init,
                    event_sender,
                    action_receiver,
                    http_state,
                ),
                FetchChannels::Prefetch => {
                    self.resource_manager
                        .fetch(runtime, req_init, None, DiscardFetch, http_state, None)
                        .await;
                },
            },
            CoreResourceMsg::DeleteCookies(request) => {
                http_state
                    .cookie_jar
                    .write()
                    .unwrap()
                    .clear_storage(&request);
                self.persist_cookies(http_state);
                return true;
            },            
            CoreResourceMsg::FetchRedirect(req_init, res_init, sender, cancel_chan) => {
                self.resource_manager
                    .fetch(
                        runtime,
                        req_init,
                        Some(res_init),
                        sender,
                        http_state,
                        cancel_chan,
                    )
                    .await
            },
            CoreResourceMsg::SetCookieForUrl(request, cookie, source) => self
                .resource_manager
                .set_cookie_for_url(&request, cookie.into_inner(), source, http_state),
            CoreResourceMsg::SetCookiesForUrl(request, cookies, source) => {
                for cookie in cookies {
                    self.resource_manager.set_cookie_for_url(
                        &request,
                        cookie.into_inner(),
                        source,
                        http_state,
                    );
                }
                self.persist_cookies(http_state);
            },
            CoreResourceMsg::GetCookiesForUrl(url, consumer, source) => {
                let mut cookie_jar = http_state.cookie_jar.write().unwrap();
                cookie_jar.remove_expired_cookies_for_url(&url);
                consumer
                    .send(cookie_jar.cookies_for_url(&url, source))
                    .unwrap();
            },
            CoreResourceMsg::NetworkMediator(mediator_chan, origin) => {
                self.resource_manager
                    .sw_managers
                    .insert(origin, mediator_chan);
            },
            CoreResourceMsg::GetCookiesDataForUrl(url, consumer, source) => {
                let mut cookie_jar = http_state.cookie_jar.write().unwrap();
                cookie_jar.remove_expired_cookies_for_url(&url);
                let cookies = cookie_jar
                    .cookies_data_for_url(&url, source)
                    .map(Serde)
                    .collect();
                consumer.send(cookies).unwrap();
            },
            CoreResourceMsg::GetHistoryState(history_state_id, consumer) => {
                let history_states = http_state.history_states.read().unwrap();
                consumer
                    .send(history_states.get(&history_state_id).cloned())
                    .unwrap();
            },
            CoreResourceMsg::SetHistoryState(history_state_id, structured_data) => {
                let mut history_states = http_state.history_states.write().unwrap();
                history_states.insert(history_state_id, structured_data);
            },
            CoreResourceMsg::RemoveHistoryStates(states_to_remove) => {
                let mut history_states = http_state.history_states.write().unwrap();
                for history_state in states_to_remove {
                    history_states.remove(&history_state);
                }
            },
            CoreResourceMsg::Synchronize(sender) => {
                let _ = sender.send(());
            },
            CoreResourceMsg::ClearCache => {
                http_state.http_cache.write().unwrap().clear();
            },
            CoreResourceMsg::ToFileManager(msg) => self.resource_manager.filemanager.handle(msg),

            CoreResourceMsg::Exit(sender) => {
                if let Some(ref config_dir) = self.config_dir {
                    match http_state.auth_cache.read() {
                        Ok(auth_cache) => {
                            write_json_to_file(&*auth_cache, config_dir, "auth_cache.json")
                        },
                        Err(_) => warn!("Error writing auth cache to disk"),
                    }
                    self.persist_cookies(http_state);
                    match http_state.hsts_list.read() {
                        Ok(hsts) => write_json_to_file(&*hsts, config_dir, "hsts_list.json"),
                        Err(_) => warn!("Error writing hsts list to disk"),
                    }
                }

                self.resource_manager.exit();
                let _ = sender.send(());
                return false;
            },
        }
        true
    }

    fn persist_cookies(&self, http_state: &Arc<HttpState>) {
        if let Some(ref config_dir) = self.config_dir {
            match http_state.cookie_jar.read() {
                Ok(jar) => {
                    let jar = jar.to_external();
                    write_json_to_file(&jar, config_dir, "cookie_jar.json");
                },
                Err(_) => warn!("Error writing cookie jar to disk"),
            }
        }
    }
}

pub fn read_json_from_file<T>(data: &mut T, config_dir: &Path, filename: &str)
where
    T: for<'de> Deserialize<'de>,
{
    let path = config_dir.join(filename);
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => {
            warn!("couldn't open {}: {}", display, why);
            return;
        },
        Ok(file) => file,
    };

    let mut string_buffer: String = String::new();
    match file.read_to_string(&mut string_buffer) {
        Err(why) => panic!("couldn't read from {}: {}", display, why),
        Ok(_) => debug!("successfully read from {}", display),
    }

    match serde_json::from_str(&string_buffer) {
        Ok(decoded_buffer) => *data = decoded_buffer,
        Err(why) => warn!("Could not decode buffer{}", why),
    }
}

pub fn write_json_to_file<T>(data: &T, config_dir: &Path, filename: &str)
where
    T: Serialize,
{
    let json_encoded: String;
    match serde_json::to_string_pretty(&data) {
        Ok(d) => json_encoded = d,
        Err(_) => return,
    }
    let path = config_dir.join(filename);
    let display = path.display();

    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => BufWriter::new(file),
    };

    match file.write_all(json_encoded.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", display, why),
        Ok(_) => debug!("successfully wrote to {}", display),
    }
    file.flush();
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthCacheEntry {
    pub user_name: String,
    pub password: String,
}

impl AuthCache {
    pub fn new() -> AuthCache {
        AuthCache {
            version: 1,
            entries: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthCache {
    pub version: u32,
    pub entries: HashMap<String, AuthCacheEntry>,
}

pub struct CoreResourceManager {
    user_agent: Cow<'static, str>,
    devtools_chan: Option<Sender<DevtoolsControlMsg>>,
    sw_managers: HashMap<ImmutableOrigin, IpcSender<CustomResponseMediator>>,
    filemanager: FileManager,
    certificate_path: Option<String>,
}

unsafe impl Sync for CoreResourceManager {}
unsafe impl Send for CoreResourceManager {}

impl CoreResourceManager {
    pub fn new(
        user_agent: Cow<'static, str>,
        devtools_channel: Option<Sender<DevtoolsControlMsg>>,
        embedder_proxy: EmbedderProxy,
        certificate_path: Option<String>,
    ) -> CoreResourceManager {
        CoreResourceManager {
            user_agent: user_agent,
            devtools_chan: devtools_channel,
            sw_managers: Default::default(),
            filemanager: FileManager::new(embedder_proxy),
            certificate_path,
        }
    }

    /// Exit the core resource manager.
    pub fn exit(&mut self) {
        // Prevents further work from being spawned on the pool,
        // blocks until all workers in the pool are done,
        // or a short timeout has been reached.

        // Shut-down the async runtime used by websocket workers.
        drop(WS_HANDLE.lock().unwrap().take());

        debug!("Exited CoreResourceManager");
    }

    fn set_cookie_for_url(
        &mut self,
        request: &ServoUrl,
        cookie: cookie_rs::Cookie<'static>,
        source: CookieSource,
        http_state: &Arc<HttpState>,
    ) {
        if let Some(cookie) = cookie::Cookie::new_wrapped(cookie, request, source) {
            let mut cookie_jar = http_state.cookie_jar.write().unwrap();
            cookie_jar.push(cookie, request, source)
        }
    }

    async fn fetch<Target: 'static + FetchTaskTarget + Send>(
        &self,
        runtime: &'static Runtime,
        request_builder: RequestBuilder,
        res_init_: Option<ResponseInit>,
        mut sender: Target,
        http_state: &Arc<HttpState>,
        cancel_chan: Option<IpcReceiver<()>>,
    ) {
        let http_state = http_state.clone();
        let ua = self.user_agent.clone();
        let dc = self.devtools_chan.clone();
        let filemanager = self.filemanager.clone();

        let timing_type = match request_builder.destination {
            Destination::Document => ResourceTimingType::Navigation,
            _ => ResourceTimingType::Resource,
        };

        let mut request = request_builder.build();
        let url = request.current_url();

        // In the case of a valid blob URL, acquiring a token granting access to a file,
        // regardless if the URL is revoked after token acquisition.
        //
        // TODO: to make more tests pass, acquire this token earlier,
        // probably in a separate message flow.
        //
        // In such a setup, the token would not be acquired here,
        // but could instead be contained in the actual CoreResourceMsg::Fetch message.
        //
        // See https://github.com/servo/servo/issues/25226
        let (file_token, blob_url_file_id) = match url.scheme() {
            "blob" => {
                if let Ok((id, _)) = parse_blob_url(&url) {
                    (self.filemanager.get_token_for_file(&id), Some(id))
                } else {
                    (FileTokenCheck::ShouldFail, None)
                }
            },
            _ => (FileTokenCheck::NotRequired, None),
        };

        // XXXManishearth: Check origin against pipeline id (also ensure that the mode is allowed)
        // todo load context / mimesniff in fetch
        // todo referrer policy?
        // todo service worker stuff
        let context = FetchContext {
            runtime: runtime,
            state: http_state,
            user_agent: ua,
            devtools_chan: dc.map(|dc| Arc::new(Mutex::new(dc))),
            filemanager: Arc::new(Mutex::new(filemanager)),
            file_token,
            cancellation_listener: Arc::new(Mutex::new(CancellationListener::new(cancel_chan))),
            timing: ServoArc::new(Mutex::new(ResourceFetchTiming::new(request.timing_type()))),
        };

        match res_init_ {
            Some(res_init) => {
                let response = Response::from_init(res_init, timing_type);
                http_redirect_fetch(
                    &mut request,
                    &mut CorsCache::new(),
                    response,
                    true,
                    &mut sender,
                    &mut None,
                    &context,
                )
                .await;
            },
            None => {
                fetch(&mut request, &mut sender, &context).await;
            },
        };

        // Remove token after fetch.
        if let Some(id) = blob_url_file_id.as_ref() {
            context
                .filemanager
                .lock()
                .unwrap()
                .invalidate_token(&context.file_token, id);
        }
    }

    fn websocket_connect(
        &self,
        request: RequestBuilder,
        event_sender: IpcSender<WebSocketNetworkEvent>,
        action_receiver: IpcReceiver<WebSocketDomAction>,
        http_state: &Arc<HttpState>,
    ) {
        websocket_loader::init(
            request,
            event_sender,
            action_receiver,
            http_state.clone(),
            self.certificate_path.clone(),
        );
    }
}
