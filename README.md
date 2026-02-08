


# code explanation 

### type Access: 
each access object represent for an access that some app or someone has to something

### kind:
means who has access app, group or user. possible values:
- "User"
- "Group"
- "ServiceAccount"

### name:
name of the subject, depends on what is the value of kind

### namespace:
for users and group are empty and for serviceAccount is the namespace of the service

### namespaces:
tells that this access is namespaced or not

### roleRefKind: 
represent the type of role being referenced. possible values:
- "Role"
- "ClusterRole"

### roleRefName:
role name

### binding:
name of the binding object that grants the access.

### example:
```
kind: RoleBinding
metadata:
  name: view-binding
  namespace: dev
subjects:
- kind: User
  name: alice
roleRef:
  kind: Role
  name: view
```
turns into 
```
Access{
    kind:        "User",
    name:        "alice",
    namespace:   "dev",
    namespaced:  true,
    roleRefKind: "Role",
    roleRefName: "view",
    binding:     "RoleBinding/dev/view-binding",
}
```


