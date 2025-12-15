use axum::response::Html;

pub async fn home_page() -> Html<&'static str> {
    Html(r#"
    <html>
        <head>
            <title>J-Secure Cloud Rust</title>
            <style>
                body { font-family: sans-serif; text-align: center; margin-top: 80px; }
                h1 { font-size: 48px; }
            </style>
        </head>
        <body>
            <h1>🚀 J-Secure Cloud Rust</h1>
            <p>Serveur Axum en ligne et structuré proprement.</p>
            <p><code>GET /api/health</code> → test API</p>
        </body>
    </html>
    "#)
}
