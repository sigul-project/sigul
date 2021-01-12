use std::fs::File;
use std::env;
use std::io::prelude::*;

fn main() {
    let mut args = env::args();
    // Skip the command name
    args.next();

    let rpm_file_name = args.next().expect("RPM file name expected");
    let extracted_file_name = args.next().expect("Extracted file name expected");

    let pkg_f = File::open(rpm_file_name).expect("Unable to open RPM file");
    let mut pkg_reader = std::io::BufReader::new(pkg_f);
    let pkg = rpm::RPMPackage::parse(&mut pkg_reader).expect("Unable to parse RPM");

    let ima_signatures = pkg.metadata.signature.get_file_ima_signatures().expect("Unable to extract IMA signatures");

    match ima_signatures.len() {
        0 => panic!("No IMA signatures found"),
        1 => {},
        n => panic!(format!("Too many IMA signatures found: {}", n)),
    }

    let ima_signature = &ima_signatures[0];
    let ima_signature = hex::decode(ima_signature).expect("Unable to hex-decode signature");

    let mut out_file = File::create(format!("{}.sig", extracted_file_name)).expect("Unable to open out file");
    out_file.write_all(&ima_signature).expect("Unable to write signature file");
}
