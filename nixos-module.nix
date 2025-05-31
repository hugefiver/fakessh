{
  config,
  lib,
  pkgs,
  self,
  ...
}:
with lib; let
  cfg = config.services.fakessh;
in {
  options.services.fakessh = {
    enable = mkEnableOption "Fake SSH Server service";

    package = mkPackageOption pkgs "fakessh" {
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.fakessh;
    };

    port = mkOption {
      type = types.port;
      default = 2222;
      description = "Port number to listen on.";
    };

    hostKey = mkOption {
      type = types.path;
      default = "/etc/fakessh/ssh_host_key";
      description = "Path to the host private key file.";
      example = "/etc/fakessh/ssh_host_key";
    };

    generateHostKey = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to automatically generate the SSH host key if it doesn't exist.";
    };

    hostKeyOption = mkOption {
      type = types.string;
      default = "ed25519";
      description = "Number of bits for the host key when automatically generating one.";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the configuration file.";
    };

    extraConfig = mkOption {
      type = types.attrs;
      default = {};
      description = "Extra configuration options to be written to the config file if configFile is not specified.";
    };
  };

  config = mkIf cfg.enable {
    users.groups.fakessh = {};
    users.users.fakessh = {
      group = "fakessh";
      isSystemUser = true;
    };

    systemd.tmpfiles.rules =
      [
        "d /etc/fakessh 0750 root fakessh -"
      ]
      ++ optionals (cfg.configFile == null) [
        "f /etc/fakessh/config.toml 0640 root fakessh -"
      ];

    environment.etc."fakessh/config.toml".text =
      mkIf (cfg.configFile == null)
      (generators.toTOML {} cfg.extraConfig);

    systemd.services.fakessh-keygen = mkIf cfg.generateHostKey {
      description = "Generate FakeSSH Host Key";
      wantedBy = ["fakessh.service"];
      before = ["fakessh.service"];
      path = [pkgs.openssh];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "fakessh";
        ExecStart = toString (pkgs.writeShellScript "generate-fakessh-key" ''
          if [ ! -f "${cfg.hostKey}" ]; then
            echo "Generating new SSH host key..."
            ${cfg.package}/bin/fakessh -gen -key "${cfg.hostKey}" -type "${cfg.hostKeyOption}"
            chown root:fakessh "${cfg.hostKey}"
            chmod 640 "${cfg.hostKey}"
          fi
        '');
      };
    };
    systemd.services.fakessh = {
      description = "Fake SSH Server";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];
      requires = mkIf cfg.generateHostKey ["fakessh-keygen.service"];

      serviceConfig = {
        ExecStart = concatStringsSep " " ([
            "${cfg.package}/bin/fakessh"
            "-port ${toString cfg.port}"
            "-key ${cfg.hostKey}"
          ]
          ++ optional (cfg.configFile != null) "-config ${cfg.configFile}"
          ++ optional (cfg.configFile == null) "-config /etc/fakessh/config.toml");
        Restart = "always";
        RestartSec = "30";
        Type = "simple";

        User = "fakessh";
        Group = "fakessh";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateDevices = true;
        PrivateTmp = true;
      };
    };
  };
}
