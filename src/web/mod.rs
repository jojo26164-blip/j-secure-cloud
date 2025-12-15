use axum::{
    response::Html,
    routing::get,
    Router,
};

pub fn web_router() -> Router {
    Router::new()
        .route("/", get(home_page))
}

async fn home_page() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <title>J-Secure Cloud</title>
    <style>
      body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #0f172a;
        color: #e5e7eb;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        margin: 0;
      }
      .card {
        background: #020617;
        border-radius: 16px;
        padding: 24px 28px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        max-width: 420px;
        width: 90%;
      }
      h1 {
        margin-top: 0;
        margin-bottom: 12px;
        font-size: 1.8rem;
        text-align: center;
      }
      .subtitle {
        font-size: 0.9rem;
        color: #9ca3af;
        text-align: center;
        margin-bottom: 16px;
      }
      .status {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        margin: 10px 0 18px;
        font-size: 0.95rem;
      }
      .dot {
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background: #f97316;
      }
      .status-ok .dot {
        background: #22c55e;
      }
      .status-error .dot {
        background: #ef4444;
      }
      .endpoint {
        font-family: monospace;
        font-size: 0.8rem;
        background: #020617;
        border-radius: 8px;
        padding: 8px 10px;
        border: 1px solid #1f2937;
        margin-top: 8px;
        word-break: break-all;
        color: #e5e7eb;
      }
      .small {
        font-size: 0.75rem;
        color: #6b7280;
        text-align: center;
        margin-top: 12px;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>J-Secure Cloud</h1>
      <div class="subtitle">
        Serveur Rust (Axum) – Statut en temps réel
      </div>

      <div id="status" class="status">
        <div class="dot"></div>
        <span>Vérification du serveur...</span>
      </div>

      <div>
        <div>Endpoint de santé :</div>
        <div class="endpoint">GET /health</div>
      </div>

      <div class="small">
        Ouvre cette page depuis ton téléphone :<br />
        <strong>http://192.168.1.211:9200/</strong>
      </div>
    </div>

    <script>
      async function checkHealth() {
        const el = document.getElementById("status");

        try {
          const res = await fetch("/health");
          if (!res.ok) {
            el.className = "status status-error";
            el.innerHTML = '<div class="dot"></div><span>Serveur en erreur (' + res.status + ')</span>';
            return;
          }
          const text = await res.text();

          el.className = "status status-ok";
          el.innerHTML = '<div class="dot"></div><span>Serveur en ligne (' + text + ')</span>';
        } catch (e) {
          el.className = "status status-error";
          el.innerHTML = '<div class="dot"></div><span>Impossible de joindre /health</span>';
        }
      }

      checkHealth();
      setInterval(checkHealth, 5000);
    </script>
  </body>
</html>
"#)
}
