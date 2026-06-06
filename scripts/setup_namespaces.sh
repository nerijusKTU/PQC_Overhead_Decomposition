#!/bin/bash
set -e

# Valyti jei liko iš ankstesnio karto
sudo ip netns del ns_client 2>/dev/null || true
sudo ip netns del ns_server 2>/dev/null || true
sudo ip link del veth-cli 2>/dev/null || true

# Sukurti
sudo ip netns add ns_client
sudo ip netns add ns_server
sudo ip link add veth-cli type veth peer name veth-srv
sudo ip link set veth-cli netns ns_client
sudo ip link set veth-srv netns ns_server

# IP adresai
sudo ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth-cli
sudo ip netns exec ns_server ip addr add 10.0.0.1/24 dev veth-srv

# Aktyvuoti
sudo ip netns exec ns_client ip link set veth-cli up
sudo ip netns exec ns_server ip link set veth-srv up
sudo ip netns exec ns_client ip link set lo up
sudo ip netns exec ns_server ip link set lo up

# Patikrinti
echo "Tikrinama..."
sudo ip netns exec ns_client ping -c 1 10.0.0.1 && echo "✓ Veikia!" || echo "✗ Klaida!"
