use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;

use twitter_v2::{authorization::{Oauth2Client, Oauth2Token, Scope, BearerToken}, query::TweetField};
use twitter_v2::oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use twitter_v2::TwitterApi;

pub struct Oauth2Ctx {
    client: Oauth2Client,
    verifier: Option<PkceCodeVerifier>,
    state: Option<CsrfToken>,
    token: Option<Oauth2Token>,
}

async fn login(Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>) -> impl IntoResponse {
    let mut ctx = ctx.lock().unwrap();
    // create challenge
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    // create authorization url
    let (url, state) = ctx.client.auth_url(
        challenge,
        [
            Scope::TweetRead,
            Scope::TweetWrite,
            Scope::UsersRead,
            Scope::OfflineAccess,
        ],
    );
    // set context for reference in callback
    ctx.verifier = Some(verifier);
    ctx.state = Some(state);
    // redirect user
    // let redirect_url = url.to_string().parse().unwrap();

    tracing::info!("Redirecting to {}", url);

    // Redirect::to(redirect_url);
    Redirect::to(url.to_string().parse().unwrap())
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: AuthorizationCode,
    state: CsrfToken,
}

async fn callback(
    Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>,
    Query(CallbackParams { code, state }): Query<CallbackParams>,
) -> impl IntoResponse {
    let (client, verifier) = {
        let mut ctx = ctx.lock().unwrap();
        // get previous state from ctx (see login)
        let saved_state = ctx.state.take().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No previous state found".to_string(),
            )
        })?;
        // // check state returned to see if it matches, otherwise throw an error
        if state.secret() != saved_state.secret() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid state returned".to_string(),
            ));
        }
        // // get verifier from ctx
        let verifier = ctx.verifier.take().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No PKCE verifier found".to_string(),
            )
        })?;
        let client = ctx.client.clone();
        (client, verifier)
    };

    // request oauth2 token
    let token = client
        .request_token(code, verifier)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // set context for use with twitter API
    ctx.lock().unwrap().token = Some(token);

    // Ok(Redirect::to("/debug_token".parse().unwrap()))
    //Ok(Redirect::to("/tweets".parse().unwrap()))
    Ok(Redirect::to("/my_get_tweet".parse().unwrap()))
}

async fn tweets(Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>) -> impl IntoResponse {
    // get oauth token
    let (mut oauth_token, oauth_client) = {
        let ctx = ctx.lock().unwrap();
        let token = ctx
            .token
            .as_ref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not logged in!".to_string()))?
            .clone();
        let client = ctx.client.clone();
        (token, client)
    };
    // refresh oauth token if expired
    if oauth_client
        .refresh_token_if_expired(&mut oauth_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        // save oauth token if refreshed
        ctx.lock().unwrap().token = Some(oauth_token.clone());
    }

    // oauth_client.request_token(code, verifier)


    // let oauth_token = ctx
    //     .lock()
    //     .unwrap()
    //     .token
    //     .as_ref()
    //     .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not logged in!".to_string()))?
    //     .clone();



    let api = TwitterApi::new(oauth_token);
    // get tweet by id
    //.with_user_ctx()
    //.await?
    //.get_my_tweets()
    let tweet = api
        .get_tweet(20)
        .send()
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok::<_, (StatusCode, String)>(Json(tweet.into_data()))
}

async fn revoke(Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>) -> impl IntoResponse {
    // get oath token
    let (oauth_token, oauth_client) = {
        let ctx = ctx.lock().unwrap();
        let token = ctx
        .token
        .as_ref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not logged in!".to_string()))?
        .clone();
        let client = ctx.client.clone();
        (token, client)
    };
    // revoke token
    oauth_client
        .revoke_token(oauth_token.revokable_token())
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok::<_, (StatusCode, String)>("Token revoked!")
}

async fn debug_token(Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>) -> impl IntoResponse {
    // get oauth token
    let oauth_token = ctx
        .lock()
        .unwrap()
        .token
        .as_ref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not logged in!".to_string()))?
        .clone();
    // get underlying token
    Ok::<_, (StatusCode, String)>(Json(oauth_token))
}

async fn my_get_tweet(Extension(ctx): Extension<Arc<Mutex<Oauth2Ctx>>>) -> impl IntoResponse {

    //let auth = BearerToken::new(std::env::var("APP_BEARER_TOKEN").unwrap());
    let bearer_token =  ctx
        .lock()
        .unwrap()
        .token
        .as_ref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not logged in!".to_string()))?
        .access_token()
        .clone();
    // BearerToken::new(std::format!("{:?}",
    tracing::info!("Bearer token: {:?}", bearer_token.secret());

    let tweet = TwitterApi::new(BearerToken::new(bearer_token.secret()))
        .get_tweet(1261326399320715264)
        .tweet_fields([TweetField::AuthorId, TweetField::CreatedAt])
        .send()
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok::<_, (StatusCode, String)>(Json(tweet.into_data().unwrap()))
        //.await?
        //.into_data()
        //.expect("this tweet should exist");
    // assert_eq!(tweet.id, 1261326399320715264);
    // assert_eq!(tweet.author_id.unwrap(), 2244994945);
    // assert_eq!(tweet.created_at.unwrap(), datetime!(2020-05-15 16:03:42 UTC));
    // Ok::<_, (StatusCode, String)>(Json(tweet)))
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "oauth2_callback=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // serve on port 3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let client_id = std::env::var("CLIENT_ID").expect("could not find CLIENT_ID"); 
    let client_secret = std::env::var("CLIENT_SECRET").expect("could not find CLIENT_SECRET");

    // println!("{}\n{}", client_id, client_secret);
    // let auth = BearerToken::new(std::env::var("APP_BEARER_TOKEN").unwrap());
    // initialize Oauth2Client with ID and Secret and the callback to this server
    let oauth_ctx = Oauth2Ctx {
        client: Oauth2Client::new(
            client_id,
            client_secret,
            format!("http://{addr}/callback").parse().unwrap(),
        ),
        verifier: None,
        state: None,
        token: None,
    };

    // initialize server
    let app = Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/my_get_tweet", get(my_get_tweet))
        .route("/tweets", get(tweets))
        .route("/revoke", get(revoke))
        .route("/debug_token", get(debug_token))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(Arc::new(Mutex::new(oauth_ctx))));

    // run server
    tracing::info!("\nOpen http://{}/login in your browser\n", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
