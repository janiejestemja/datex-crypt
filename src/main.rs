use datex_crypt::{client, server};

#[tokio::main]
async fn main() {

    #[cfg(feature = "client")]
    {
        client().await;
    }

    #[cfg(feature = "server")]
    {
        server().await;
    }
}
