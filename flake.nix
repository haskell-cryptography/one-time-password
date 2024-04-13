{
  description = "one-time-password";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    libsodium-bindings.url = "github:haskell-cryptography/libsodium-bindings";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs{inherit system;};
      in
      rec
      {
        packages.one-time-password =
          pkgs.haskellPackages.callCabal2nix "one-time-password" ./.
            {
              base32 = pkgs.haskellPackages.base32_0_4;
              sel = inputs.libsodium-bindings.packages.${system}.sel;
            };

        defaultPackage = packages.one-time-password;

        devShell =
          let
            scripts = pkgs.symlinkJoin {
              name = "scripts";
              paths = pkgs.lib.mapAttrsToList pkgs.writeShellScriptBin {
              };
            };
          in
          pkgs.mkShell {
            buildInputs = with pkgs.haskellPackages; [
              pkgs.libsodium
              haskell-language-server
              ghcid
              cabal-install
              scripts
            ];
            inputsFrom = [
              self.defaultPackage.${system}.env
            ];
          };
      });
}
