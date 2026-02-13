


## i am using this package that has some vulnerabilities on it 
### rbacv1 "k8s.io/api/rbac/v1"


# task: i should check each package version to be safe to use in production


manifest that i apply without helm:
secret of elasticsearch on k8s


commands that need to be applied and has been applied: 

k create configmap input-reader -n <namespace> ---from-file=inpu.json=./json-files/input.json

what i have applied: k create configmap input-reader -n audit-logs --from-file=input.json=./json-files/input.json

