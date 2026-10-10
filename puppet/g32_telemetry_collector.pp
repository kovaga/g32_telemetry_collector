# @summary Install and run the Otto Wilde G32 telemetry collector.
#
# Hiera: every class parameter below is resolved with an explicit lookup().
#
# Requires puppet/systemd >= 8.3.0 for LoadCredential support in
# systemd::manage_unit.
class packages::g32_telemetry_collector (
  String[1] $tzsp_bind = lookup('packages::g32_telemetry_collector::tzsp_bind', {
    'default_value' => '0.0.0.0',
    'merge'         => 'first',
  }),
  Integer[1, 65535] $tzsp_port = lookup('packages::g32_telemetry_collector::tzsp_port', {
    'default_value' => 37009,
    'merge'         => 'first',
  }),
  String[1] $grill_ip = lookup('packages::g32_telemetry_collector::grill_ip', {
    'default_value' => '192.168.6.103',
    'merge'         => 'first',
  }),
  Integer[1, 65535] $grill_tcp_port = lookup('packages::g32_telemetry_collector::grill_tcp_port', {
    'default_value' => 4501,
    'merge'         => 'first',
  }),
  String[8, 8] $device_id = lookup('packages::g32_telemetry_collector::device_id', {
    'default_value' => '84e0422c',
    'merge'         => 'first',
  }),
  Optional[Integer[0]] $tare_weight_g = lookup('packages::g32_telemetry_collector::tare_weight_g', {
    'default_value' => undef,
    'merge'         => 'first',
  }),
  String[1] $timezone = lookup('packages::g32_telemetry_collector::timezone', {
    'default_value' => 'UTC',
    'merge'         => 'first',
  }),
  Boolean $human_output = lookup('packages::g32_telemetry_collector::human_output', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  Boolean $pretty_output = lookup('packages::g32_telemetry_collector::pretty_output', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  Boolean $include_rawframe = lookup('packages::g32_telemetry_collector::include_rawframe', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  Boolean $verbose = lookup('packages::g32_telemetry_collector::verbose', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  Integer[1] $offline_after = lookup('packages::g32_telemetry_collector::offline_after', {
    'default_value' => 60,
    'merge'         => 'first',
  }),
  Boolean $http_enabled = lookup('packages::g32_telemetry_collector::http_enabled', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  String[1] $http_bind = lookup('packages::g32_telemetry_collector::http_bind', {
    'default_value' => '127.0.0.1',
    'merge'         => 'first',
  }),
  Integer[1, 65535] $http_port = lookup('packages::g32_telemetry_collector::http_port', {
    'default_value' => 8765,
    'merge'         => 'first',
  }),
  String[1] $http_path = lookup('packages::g32_telemetry_collector::http_path', {
    'default_value' => '/g32',
    'merge'         => 'first',
  }),
  Boolean $mqtt_enabled = lookup('packages::g32_telemetry_collector::mqtt_enabled', {
    'default_value' => true,
    'merge'         => 'first',
  }),
  Optional[Variant[String[1], Sensitive[String[1]]]] $mqtt_password = lookup('packages::g32_telemetry_collector::mqtt_password', {
    'default_value' => undef,
    'merge'         => 'first',
  }),
  String[1] $mqtt_username = lookup('packages::g32_telemetry_collector::mqtt_username', {
    'default_value' => 'mqttuser',
    'merge'         => 'first',
  }),
  String[1] $mqtt_host = lookup('packages::g32_telemetry_collector::mqtt_host', {
    'default_value' => '192.168.9.12',
    'merge'         => 'first',
  }),
  Integer[1, 65535] $mqtt_port = lookup('packages::g32_telemetry_collector::mqtt_port', {
    'default_value' => 1883,
    'merge'         => 'first',
  }),
  String[1] $mqtt_topic = lookup('packages::g32_telemetry_collector::mqtt_topic', {
    'default_value' => 'openhab/g32/status',
    'merge'         => 'first',
  }),
  Integer[0, 2] $mqtt_qos = lookup('packages::g32_telemetry_collector::mqtt_qos', {
    'default_value' => 1,
    'merge'         => 'first',
  }),
  Boolean $mqtt_retain = lookup('packages::g32_telemetry_collector::mqtt_retain', {
    'default_value' => true,
    'merge'         => 'first',
  }),
  String[1] $mqtt_client_id = lookup('packages::g32_telemetry_collector::mqtt_client_id', {
    'default_value' => 'g32_telemetry_collector',
    'merge'         => 'first',
  }),
  Boolean $mqtt_tls = lookup('packages::g32_telemetry_collector::mqtt_tls', {
    'default_value' => false,
    'merge'         => 'first',
  }),
  Stdlib::Absolutepath $install_dir = lookup('packages::g32_telemetry_collector::install_dir', {
    'default_value' => '/opt/g32_telemetry_collector',
    'merge'         => 'first',
  }),
) {
  # The password is required only when MQTT publishing is enabled.
  $required_params = $mqtt_enabled ? {
    true    => { 'mqtt_password' => $mqtt_password },
    default => {},
  }

  $missing_params = $required_params.filter |String $name, Any $value| {
    $value == undef
  }

  if !empty($missing_params) {
    $missing_param_names = $missing_params.keys.join(', ')
    fail("Required Hiera parameter(s) not defined: ${missing_param_names}")
  }

  $mqtt_password_sensitive = $mqtt_password ? {
    Sensitive => $mqtt_password,
    String    => Sensitive($mqtt_password),
    default   => undef,
  }

  $collector_path = "${install_dir}/g32_telemetry_collector.py"
  $config_path    = "${install_dir}/g32_telemetry_collector.conf"

  $exec_start = "${collector_path} --config %d/collector-config"

  package { 'python3-paho-mqtt':
    ensure => installed,
  }

  file { $install_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { $collector_path:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/packages/g32_telemetry_collector/g32_telemetry_collector.py',
    require => [
      Package['python3-paho-mqtt'],
      File[$install_dir],
    ],
  }

  file { $config_path:
    ensure    => file,
    owner     => 'root',
    group     => 'root',
    mode      => '0600',
    show_diff => false,
    content   => epp('packages/g32_telemetry_collector/g32_telemetry_collector.conf.epp', {
      'tzsp_bind'          => $tzsp_bind,
      'tzsp_port'          => $tzsp_port,
      'grill_ip'           => $grill_ip,
      'grill_tcp_port'     => $grill_tcp_port,
      'device_id'          => $device_id,
      'tare_weight_g'      => $tare_weight_g,
      'timezone'           => $timezone,
      'human_output'       => $human_output,
      'pretty_output'      => $pretty_output,
      'include_rawframe'   => $include_rawframe,
      'verbose'            => $verbose,
      'offline_after'      => $offline_after,
      'http_enabled'       => $http_enabled,
      'http_bind'          => $http_bind,
      'http_port'          => $http_port,
      'http_path'          => $http_path,
      'mqtt_enabled'       => $mqtt_enabled,
      'mqtt_host'          => $mqtt_host,
      'mqtt_port'          => $mqtt_port,
      'mqtt_topic'         => $mqtt_topic,
      'mqtt_qos'           => $mqtt_qos,
      'mqtt_retain'        => $mqtt_retain,
      'mqtt_client_id'     => $mqtt_client_id,
      'mqtt_username'      => $mqtt_username,
      'mqtt_password'      => $mqtt_password_sensitive,
      'mqtt_tls'           => $mqtt_tls,
    }),
    require   => File[$install_dir],
  }

  systemd::manage_unit { 'g32_telemetry_collector.service':
    ensure             => present,
    enable             => true,
    active             => true,
    unit_entry         => {
      'Description'           => 'Otto Wilde G32 telemetry collector',
      'Wants'                 => 'network-online.target',
      'After'                 => 'network-online.target',
      'StartLimitIntervalSec' => '60',
      'StartLimitBurst'       => 5,
    },
    service_entry      => {
      'Type'                    => 'simple',
      'DynamicUser'             => true,
      'LoadCredential'          => "collector-config:${config_path}",
      'ExecStart'               => $exec_start,
      'Restart'                 => 'on-failure',
      'RestartSec'              => '5s',
      'KillSignal'              => 'SIGINT',
      'TimeoutStopSec'          => '15s',
      'StandardOutput'          => 'null',
      'StandardError'           => 'journal',
      'SyslogIdentifier'        => 'g32_telemetry_collector',
      'UMask'                   => '0077',
      'NoNewPrivileges'         => true,
      'PrivateDevices'          => true,
      'PrivateTmp'              => true,
      'ProtectClock'            => true,
      'ProtectControlGroups'    => true,
      'ProtectHome'             => true,
      'ProtectHostname'         => true,
      'ProtectKernelLogs'       => true,
      'ProtectKernelModules'    => true,
      'ProtectKernelTunables'   => true,
      'ProtectProc'             => 'invisible',
      'ProtectSystem'           => 'strict',
      'RestrictAddressFamilies' => ['AF_INET', 'AF_INET6'],
      'RestrictNamespaces'      => true,
      'RestrictRealtime'        => true,
      'RestrictSUIDSGID'        => true,
      'LockPersonality'         => true,
      'MemoryDenyWriteExecute'  => true,
      'SystemCallArchitectures' => 'native',
      'TasksMax'                => 64,
    },
    install_entry      => {
      'WantedBy' => 'multi-user.target',
    },
    service_parameters => {
      'subscribe' => [
        File[$collector_path],
        File[$config_path],
      ],
    },
    require            => [
      Package['python3-paho-mqtt'],
      File[$collector_path],
      File[$config_path],
    ],
  }
}
