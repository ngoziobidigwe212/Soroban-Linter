fn main() {
    std::process::exit(soroban_linter::cli::run(std::env::args_os()));
}
