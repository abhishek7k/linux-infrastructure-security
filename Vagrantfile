# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Global configurations
  config.vagrant.plugins = ["vagrant-disksize"] if Vagrant.has_plugin?("vagrant-disksize")

  # ----------------------------------------------------
  # Target Server Node: Arch Linux
  # ----------------------------------------------------
  config.vm.define "arch-node" do |arch|
    arch.vm.box = "archlinux/archlinux"
    arch.vm.hostname = "secops-arch-server"
    
    # Private network for isolated security testing
    arch.vm.network "private_network", ip: "192.168.56.20", name: "vboxnet0", adapter: 2
    
    # Provider-specific configurations
    arch.vm.provider "virtualbox" do |vb|
      vb.name = "SecOps-Arch-Server"
      vb.memory = "2048"
      vb.cpus = 2
      vb.customize ["modifyvm", :id, "--groups", "/Linux-Security-Lab"]
    end

    # Provisioning: Copy hardening configs and run scripts
    arch.vm.provision "file", source: "scripts/", destination: "/tmp/scripts"
    arch.vm.provision "file", source: "configs/", destination: "/tmp/configs"
    
    arch.vm.provision "shell", inline: <<-SHELL
      echo "[*] Launching system hardening scripts..."
      chmod +x /tmp/scripts/*.sh
      sudo /tmp/scripts/hardening.sh --non-interactive
      sudo /tmp/scripts/network_setup.sh --node server
    SHELL
  end

  # ----------------------------------------------------
  # Attacker / Auditor Node: Kali Linux
  # ----------------------------------------------------
  config.vm.define "kali-node" do |kali|
    kali.vm.box = "kalilinux/kali-rolling"
    kali.vm.hostname = "secops-kali-attacker"
    
    # Private network link to access the server
    kali.vm.network "private_network", ip: "192.168.56.10", name: "vboxnet0", adapter: 2
    
    # Provider-specific configurations
    kali.vm.provider "virtualbox" do |vb|
      vb.name = "SecOps-Kali-Attacker"
      vb.memory = "4096"
      vb.cpus = 2
      vb.customize ["modifyvm", :id, "--groups", "/Linux-Security-Lab"]
    end

    # Provisioning: Set up tools and network controls
    kali.vm.provision "file", source: "scripts/network_setup.sh", destination: "/tmp/network_setup.sh"
    
    kali.vm.provision "shell", inline: <<-SHELL
      echo "[*] Setting up network access verification..."
      chmod +x /tmp/network_setup.sh
      sudo /tmp/network_setup.sh --node attacker
    SHELL
  end
end
