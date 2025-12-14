use qanvuli_collector::providers::cve::CveRelease;
use qanvuli_models::parse_json;
use qanvuli_utils::loader::{self, FileStorageTrait};

fn main() {
    println!("Hello, world!");

    let mut cve = CveRelease::new();
    let _ = cve.get();

    println!("{:?}", cve.get_latest_all_file());
    println!("{:?}", cve.get_latest_delta_file());
    println!("{:?}", cve.get_latest_delta_midnight_file());

    let asset = if let Some(a) = cve.get_latest_delta_file() {
        a
    } else {
        panic!("no asset");
    };

    if asset.download_as_file().is_err() {
        panic!("download error");
    };

    let mut storage = loader::ZipStorage::new(format!("./{}", asset.name));
    let jsons = storage.enum_json_list();
    let json = storage
        .get_json(jsons.collect::<Vec<String>>().get(0).unwrap())
        .unwrap();

    println!("{:?}", parse_json(json));
}
