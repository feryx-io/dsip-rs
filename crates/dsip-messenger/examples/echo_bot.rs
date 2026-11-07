//! A chat bot: it answers every text message with the same text, in the conversation it came from. Its state lives in
//! memory, so it starts over each run (a real bot uses a persistent `Store`, as dsip-msg does with SQLite).
//!
//! ```sh
//! dsip identity init --dir bot --name Bot --did-web did:web:bot.example
//! echo_bot doc bot <mailbox DID> wss://127.0.0.1:9443/dsip > docs/bot.json   # the document did:web serves
//! echo_bot run bot ca.pem docs/*.json -- did:web:alice.example                # prints a grant for each DID after --
//! ```
//!
//! Each DID after `--` gets a grant (M§14), printed as `GRANT <grant>`; with it that identity can create a
//! conversation with the bot and write. `demos/echo-bot-demo.sh` runs it against a mailbox, with dsip-msg writing.

use std::collections::VecDeque;
use std::path::PathBuf;

use serde_json::{json, Value};

use dsip_messaging_device::{Event, MemoryStore, Ui};
use dsip_messenger::{Config, Engine, Host, Messenger, Output};
use dsip_transport::identity::Identity;

/// Prints what happens and remembers the texts to answer.
#[derive(Default)]
struct Bot {
    identity: String,
    to_answer: VecDeque<(String, Value)>,
}

impl Host<MemoryStore> for Bot {
    async fn output(&mut self, _engine: &Engine<MemoryStore>, out: Output) {
        match out {
            Output::Event(Event::Ui(Ui::Message { group, from, object, .. })) if from != self.identity && object["kind"] == "text" => {
                println!("RECV {from}: {}", object["text"]);
                self.to_answer.push_back((group, object["text"].clone()));
            }
            Output::Event(Event::Ui(Ui::Joined { group, .. })) => println!("JOINED {group}"),
            Output::Connected { mailbox, .. } => println!("CONNECTED {mailbox}"),
            other => println!("{other:?}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: echo_bot doc <identity dir> <mailbox DID> <mailbox URI> | run <identity dir> <ca.pem> <document>... [-- <DID to grant>...]";
    let (Some(mode), Some(dir)) = (args.first(), args.get(1)) else { return Err(usage.into()) };
    let id = Identity::load(dir.as_ref())?;
    let identity = id.meta.identity.clone();
    if mode == "doc" {
        let (Some(mailbox), Some(uri)) = (args.get(2), args.get(3)) else { return Err(usage.into()) };
        println!("{}", serde_json::to_string_pretty(&dsip_messenger::did_document(&identity, id.identity_key()?, mailbox, uri))?);
        return Ok(());
    }
    let ca = args.get(2).ok_or(usage)?;
    let rest = &args[3.min(args.len())..];
    let (docs, grantees) = rest.split_at(rest.iter().position(|a| a == "--").unwrap_or(rest.len()));
    let resolver_files: Vec<PathBuf> = docs.iter().map(Into::into).collect();
    // M§4.2: the bot's own mailbox is the one its document names
    let mailbox = dsip_messenger::mailbox_of(&identity, &dsip_messenger::resolver(&resolver_files))?;

    let now = dsip_transport::now_s() as f64;
    let engine_identity = dsip_messenger::engine_identity(&identity, &id.device, id.identity_key()?, &id.delegation, &id.meta.display_name);
    let engine = Engine::open(&engine_identity, &mailbox.0, &mailbox.1, MemoryStore::default(), &Value::Null, now)?;
    let cfg = Config { identity: identity.clone(), device: id.device.clone(), delegation: id.delegation.clone(), mailbox,
                       resolver_files, ca: Some(ca.into()), media_dir: std::env::temp_dir().join("echo-bot"), host_key: "echo-bot".into() };
    let mut mx = Messenger::new(engine, cfg, vec![])?;
    let mut bot = Bot { identity: identity.clone(), ..Bot::default() };
    mx.connect(&mut bot).await?;
    let frame = mx.engine_mut().key_packages_frame(4, now)?; // so that others can add this device (M§5.5)
    mx.send_frame(&mut bot, &frame).await?;
    for did in grantees.iter().skip(1) {
        println!("GRANT {}", mx.engine_mut().grant(did, None, now));
    }
    mx.sync(&mut bot, true).await?;

    let mut clock = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            Some(frame) = mx.recv() => mx.received(&mut bot, frame).await,
            _ = clock.tick() => {
                mx.tick(&mut bot).await;
                mx.check_reconnect(&mut bot).await?;
            }
        }
        while let Some((group, text)) = bot.to_answer.pop_front() {
            let now = dsip_transport::now_s();
            let conversation = mx.engine().conversations(now as f64).into_iter().find(|c| c.group == group).map(|c| c.conversation);
            let reply = json!({"object": "content", "id": mx.engine_mut().new_id(now as f64), "conversation": conversation,
                               "sender": bot.identity, "sent_at": now, "purpose": "message",
                               "kind": "text", "content_type": "text/plain", "text": text});
            let sent = mx.engine_mut().send(&group, &reply, now as f64)?;
            if !sent.send.is_empty() {
                mx.send_frame(&mut bot, &sent.send).await?;
            }
            println!("SENT {text}");
        }
        mx.settle(&mut bot).await;
    }
}
