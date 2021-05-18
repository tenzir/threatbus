{ pkgs ? import <nixpkgs> {} }:
let
  myAppEnv = pkgs.poetry2nix.mkPoetryEnv {
    projectDir = ./.;
    editablePackageSources = {
      pyvast-threatbus = ./apps/vast;
      threatbus = ./threatbus;
      threatbus_inmem = ./plugins/backbones/threatbus_inmem;
      threatbus_rabbitmq = ./plugins/backbones/threatbus_rabbitmq;
      file_benchmark = ./plugins/backbones/file_benchmark;
      threatbus_cif3 = ./plugins/apps/threatbus_cif3;
      threatbus_misp = ./plugins/apps/threatbus_misp;
      threatbus_zeek = ./plugins/apps/threatbus_zeek;
      threatbus_zmq-app = ./plugins/apps/threatbus_zmq_app;
    };
    overrides = pkgs.poetry2nix.overrides.withDefaults (final: prev: {
      python-snappy = prev.python-snappy.overridePythonAttrs (oa: {
        buildInputs = oa.buildInputs ++ [ pkgs.snappy ];
      });
      retry = prev.retry.overridePythonAttrs (oa: {
        buildInputs = oa.buildInputs ++ [ final.pbr ];
      });
    });
  };
in
pkgs.mkShell {
  name = "threatbus-dev";
  buildInputs = [
    myAppEnv
    pkgs.zeek.py
    pkgs.poetry
    pkgs.czmq
    pkgs.rabbitmq-server
  ];

  shellHook = ''
    export RABBITMQ_LOG_BASE=$PWD/.rabbitmq/logs
    export RABBITMQ_MNESIA_BASE=$PWD/.rabbitmq/mnesia
    export PYTHONPATH="''${PYTHONPATH}''${PYTHONPATH:+:}${pkgs.zeek.py}/lib/${myAppEnv.python.libPrefix}/site-packages"
  '';
}
