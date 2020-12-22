# Show-Logs-Examples

Simple Python script that uses the Show-Logs API endpoint available in R81 or R80.40 with JHF78 or later 
to filter the logs for the past 24 hours for logs that match the Sunburst protections.  Using the filter in the script
you have the ability to change the filter to match any query you can do via SmartLog in the SmartConsole.

See the API guide for more examples of what can be done - https://sc1.checkpoint.com/documents/latest/APIs/index.html#cli/show-logs~v1.7%20

The login will be Read-Only into the SmartCenter or MDS.  

The script will loop every 5 minutes and output the top sources with a count.  A file will also be updated with the JSON data.

Example output from the script.
```
{'10.2.0.124': '2', '10.2.0.123': '5'}
```

Example useage loging into a SmartCenter at 10.1.1.1
```
./get-logs-filter-sunburst.py -u api_user -p "vpn12345" -s 10.1.1.1
```

Example useage loging into a Domain CMA3 at 10.1.1.1
```
./get-logs-filter-sunburst.py -u api_user -p "vpn12345" -s 10.1.1.1 -d CMA1
```
