{
  description = "Nix flake for hugefiver/fakessh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    fakessh-src = {
      # pinned by flake.lock; update via: nix flake lock --update-input fakessh-src
      url = "github:hugefiver/fakessh/master";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    fakessh-src,
  }:
    let
      localCommitId =
        if self ? shortRev then self.shortRev
        else if self ? dirtyShortRev then self.dirtyShortRev
        else "local";

      localVersion = "unstable-${localCommitId}";

      # Git metadata comes directly from the flake input (pinned in flake.lock)
      gitCommitId = builtins.substring 0 7 fakessh-src.rev;
      gitVersion = "unstable-git-${gitCommitId}";
      gitBuildTime = fakessh-src.lastModifiedDate;
    in
    {
      # Overlay for composability — consumers can apply this to their own pkgs
      overlays.default = _final: prev: {
        fakessh = prev.callPackage ./default.nix {
          src = ./.;
          version = localVersion;
          commitId = localCommitId;
        };
        fakessh-git = prev.callPackage ./default.nix {
          pname = "fakessh-git";
          src = fakessh-src;
          version = gitVersion;
          commitId = gitCommitId;
          buildTime = gitBuildTime;
        };
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
        fakessh = pkgs.callPackage ./default.nix {
          src = ./.;
          version = localVersion;
          commitId = localCommitId;
        };
        fakessh-git = pkgs.callPackage ./default.nix {
          pname = "fakessh-git";
          src = fakessh-src;
          version = gitVersion;
          commitId = gitCommitId;
          buildTime = gitBuildTime;
        };
        default = fakessh;
      };

      apps.default = {
        type = "app";
        program = "${self.packages.${system}.fakessh}/bin/fakessh";
        meta = self.packages.${system}.fakessh.meta;
      };

      apps.git = {
        type = "app";
        program = "${self.packages.${system}.fakessh-git}/bin/fakessh";
        meta = self.packages.${system}.fakessh-git.meta;
      };

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [ go git ];
      };
    });
}
