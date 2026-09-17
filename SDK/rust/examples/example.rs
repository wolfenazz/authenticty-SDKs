//! Authenticity SDK usage example.
//!
//! Run with: `cargo run --example example -- <ownerId> <appId> <apiUrl> <version>`

use authenticity::Client;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // args[0] is the binary path.
    let (owner, app, url, version) = match args.len() {
        5 => (args[1].clone(), args[2].clone(), args[3].clone(), args[4].clone()),
        _ => {
            eprintln!("Usage: authenticity_example <ownerId> <appId> <apiUrl> <version>");
            std::process::exit(1);
        }
    };

    let mut client = Client::new(&owner, &app, &url, &version);
    println!("HWID:          {}", client.hwid());
    println!("Computed hash: (auto)");

    // --- Login with a license key -------------------------------------------
    println!("\n=== Login ===");
    client.set_license_key("VALID_LICENSE_KEY_HERE");
    if client.login() {
        println!("Login OK!");
        println!("  username:     {}", client.session_mut().username);
        println!("  expiry:       {}", client.session_mut().expiry);
        println!("  appName:      {}", client.get_app_data().name);
        println!("  appVersion:   {}", client.get_app_data().version);
        println!("  appStatus:    {}", client.get_app_data().status);
        println!("  level:        {}", client.session_mut().level);
        println!("  hwidLock:     {}", client.get_app_data().hwid_lock);
        println!("  remaining:    {}", client.get_remaining_time());
        println!("  updateLink:   '{}'", client.get_update_link());
    } else {
        println!("Login FAILED: {}", client.get_last_error());
        std::process::exit(1);
    }

    // --- Session heartbeat ---------------------------------------------------
    println!("\n=== Check session ===");
    if client.check_session() {
        println!("Session valid.");
    } else {
        println!("Session invalid: {}", client.get_last_error());
    }

    // --- Blacklist check -----------------------------------------------------
    println!("\n=== Blacklist check ===");
    let blacklisted = client.check_blacklist();
    println!("Blacklisted: {}", blacklisted);

    // --- Variable ------------------------------------------------------------
    println!("\n=== Get variable ===");
    let value = client.get_variable("some_var");
    println!("value = '{}'", value);

    // --- Chat ----------------------------------------------------------------
    println!("\n=== Channels ===");
    for ch in client.get_channels() {
        println!("  channel: id={} name={} cooldown={}{}",
            ch.id, ch.name, ch.cooldown_time, ch.cooldown_unit);
    }

    println!("\n=== Messages (all) ===");
    for m in client.get_messages("all") {
        println!("  [{}] {}: {}", m.time_sent, m.sender, m.content);
    }

    // --- Log -----------------------------------------------------------------
    println!("\n=== Log ===");
    if client.log("example message from Rust SDK", "info") {
        println!("Log entry added.");
    } else {
        println!("Log failed: {}", client.get_last_error());
    }

    // --- Webhook -------------------------------------------------------------
    println!("\n=== Webhook ===");
    use serde_json::json;
    if client.trigger_webhook("my_webhook", json!({"hello": "world"})) {
        println!("Webhook triggered.");
    } else {
        println!("Webhook failed: {}", client.get_last_error());
    }

    // --- Credentials ----------------------------------------------------------
    println!("\n=== Save credentials ===");
    if client.save_credentials(2, "", "username", "password") {
        println!("Saved login.json next to executable.");
    }
    // Cleanup
    let _ = client.delete_credentials();

    println!("\nDone.");
}
