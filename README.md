set RESOURCE_GROUP="my-mcp-rg"
set LOCATION="australiaeast"
set ENVIRONMENT_NAME="mcp-env"
set APP_NAME="tasks-mcp-server-py"


$RESOURCE_GROUP="my-mcp-rg"
$LOCATION="australiaeast"
$ENVIRONMENT_NAME="mcp-env"
$APP_NAME="tasks-mcp-server-py"


-- create container app environment 

az group create --name $RESOURCE_GROUP --location $LOCATION

az containerapp env create --name $ENVIRONMENT_NAME  --resource-group $RESOURCE_GROUP --location $LOCATION

-- deploy container app 

az containerapp up --name $APP_NAME --resource-group $RESOURCE_GROUP --environment $ENVIRONMENT_NAME --source . --ingress external --target-port 8080

az containerapp ingress cors enable --name $APP_NAME --resource-group $RESOURCE_GROUP --allowed-origins "*" --allowed-methods "GET,POST,DELETE,OPTIONS" --allowed-headers "*"


very the deployment 

$APP_URL=$(az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.configuration.ingress.fqdn" -o tsv)


$APP_URL=https://tasks-mcp-server-py.mangomushroom-de412cce.australiaeast.azurecontainerapps.io
curl https://$APP_URL/health


az containerapp update --name $APP_NAME --resource-group $RESOURCE_GROUP --min-replicas 1
