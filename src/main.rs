use datex_crypt::{client, server};

fn main() {
    #[cfg(feature = "client")]
    {
        client();
    }

    #[cfg(feature = "server")]
    {
        server();
    }
}
