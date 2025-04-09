use rand::seq::SliceRandom;
use rand::thread_rng;
use sss_rs::split;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <secret_message> [<number_of_shares>]", args[0]);
        std::process::exit(1);
    }
    let share_count = if args.len() > 2 {
        args[2].parse::<u8>().unwrap_or(3)
    } else {
        3
    };

    println!("Number of shares: {}", share_count);

    let shares = split(args[1].as_bytes(), share_count as u8, 2).unwrap();

    println!("Shares:");
    for (i, share) in shares.iter().enumerate() {
        println!("  Share {}: {}", i, hex::encode(share));
    }
    println!();

    let mut rng = thread_rng();
    let selected_shares: Vec<_> = (0..shares.len())
        .collect::<Vec<_>>()
        .choose_multiple(&mut rng, 2)
        .cloned()
        .collect();

    println!("Randomly selected shares for reconstruction:");
    for i in &selected_shares {
        println!("  Share {}: {}", i, hex::encode(&shares[*i]));
    }
    println!();

    let selected_shares: Vec<_> = selected_shares.iter().map(|&i| shares[i].clone()).collect();

    let recovered_secret = sss_rs::combine(&selected_shares).unwrap();
    println!(
        "Reconstructed secret: {}",
        String::from_utf8(recovered_secret).unwrap()
    );
}
