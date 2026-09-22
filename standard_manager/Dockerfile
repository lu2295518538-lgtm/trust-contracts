FROM chainmakerofficial/chainmaker-vm-engine:v2.3.6
COPY contract_name /usr/local/bin/contract_name
RUN gzip -d /usr/local/bin/contract_name && chmod 755 /usr/local/bin/contract_name
CMD ["/usr/local/bin/contract_name"]
