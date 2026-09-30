{
  description = "Simple and opinionated OpenID-Connect relying party and resource server python library";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }: {

    devShells = builtins.mapAttrs (system: pkgs: {
      default = pkgs.mkShell {
        strictDeps = true;
        packages = with pkgs; [
          python3
          python3Packages.ipython
          python3Packages.platformdirs
          python3Packages.ruff
          uv
          pre-commit
        ];
        shellHook = ''
          # ensure we use dependencies installed via uv since this flake is only required for binary packages
          unset PYTHONPATH
        '';
      };
    }) nixpkgs.legacyPackages;
  };
}
