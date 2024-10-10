# Scripts Repository

Welcome to the tanbi-org/scripts repository! This repository contains scripts for reinstalling from Debian systems to the latest stable version (Debian Stable or Arch Linux), supporting Btrfs file system, ZRAM, and using systemd for time synchronization and network management.

## Script Overview

### sim.sh

The `sim.sh` script allows you to reinstall from a Debian system to the latest Debian Stable version.

#### Features
- Uses Btrfs file system
- Enables ZRAM
- Utilizes systemd-timesyncd for time synchronization
- Leverages systemd-networkd for network management

#### Parameters
- `--dhcp`: Enable DHCP functionality
- `--pwd <password>`: Set user password
- `--mirror <mirror_url>`: Specify mirror source

#### Example Usage
```bash
  bash <(wget -qO - 'https://raw.githubusercontent.com/tanbi-org/scripts/master/sim/sim.sh') --pwd 'sim@@@'
```

### sim_arch.sh
The `sim_arch.sh` script allows you to reinstall from a Debian system to the latest Arch Linux version.


#### Features
- Uses Btrfs file system
- Enables ZRAM
- Utilizes systemd-timesyncd for time synchronization
- Leverages systemd-networkd for network management

#### Parameters
- `--dhcp`: Enable DHCP functionality
- `--lts`: Use LTS linux kernel package
- `--pwd <password>`: Set user password
- `--mirror <mirror_url>`: Specify mirror source


#### Example Usage
```bash
  bash <(wget -qO - 'https://raw.githubusercontent.com/tanbi-org/scripts/master/sim/sim_arch.sh') --pwd 'sim@@@'--lts
```


## Contributing
We welcome any form of contributions! Please follow these steps:
1. **Fork** this repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push the changes to your branch (`git push origin feature/YourFeature`).
5. Submit a Pull Request.

Please ensure to follow our coding standards and provide clear descriptions when submitting.

## License

This project is licensed under the [ BSD 3 License](LICENSE). For more details, please refer to the license file.