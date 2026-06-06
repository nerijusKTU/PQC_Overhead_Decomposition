chmod +x ~/quartic/scripts/prepare_testbed.sh
chmod +x ~/quartic/scripts/run_measurements.sh

sudo ~/quartic/scripts/prepare_testbed.sh    # ~1 min
sudo ~/quartic/scripts/run_measurements.sh   # ~10 min
python3 ~/quartic/scripts/tables.py          # bet kada pakartoti
