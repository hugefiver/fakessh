{
  description = "Nix flake for hugefiver/fakessh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    {
      # Overlay for composability — consumers can apply this to their own pkgs
      overlays.default = _final: prev: {
        fakessh = prev.callPackage ./default.nix { };
      };

      nixosModules = rec {
        fakessh = import ./nixos-module.nix;
        default = fakessh;
      };
    }
    // flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages = rec {
        fakessh = pkgs.callPackage ./default.nix { };
        default = fakessh;
      };

      apps.default = {
        type = "app";
        program = "${self.packages.${system}.fakessh}/bin/fakessh";
        meta = self.packages.${system}.fakessh.meta;
      };

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [ go git ];
      };
    });
}
