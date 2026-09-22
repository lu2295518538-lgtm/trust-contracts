FROM chainmakerofficial/chainmaker-vm-engine:v2.3.6
COPY contract_name /usr/local/bin/contract_name
CMD ["/usr/local/bin/contract_name"]
