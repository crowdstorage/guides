# Signing an intermediate cert

An intermediate cert authorizes us to run your cloud harvester and keeps your private_key private.
We've made a python script to assist you.

1. Download this repo
2. Move the sign-intermediate-cert.py to your chia-blockchain folder
```
cp ~/Downloads/guides-main/sign-intermediate-cert.py ~/chia-blockchain
```
3. In the chia-blockchain directory run the following:
```
cd ~/chia-blockchain
. ./activate
python3 sign-intermediate-cert.py
```
4. Email us the signed certificate the script creates. It will be named crowdstorage_intermediate.crt
