# Android:

### 1. Add plugin
cordova plugin add https://github.com/mightymop/cordova-plugin-getmaster.git
### 2. For Typescript add following code to main ts file: 
/// &lt;reference types="cordova-plugin-getmaster" /&gt;<br/>

### 3. Before build:
install cordova-plugin-nslookup (https://github.com/mightymop/cordova-plugin-getmaster.git)
add to config.xml > platform > android

```
	    <resource-file src="www/assets/config/development.json" target="app/src/main/res/raw/development.json" />
		<resource-file src="www/assets/config/production.json" target="app/src/main/res/raw/production.json" />
```

### 4. Usage:

methods:

```
	var users : string[] = ['user1','user2']
	window.getmaster.getUserSecrets(user,ssuccess,err);
	
	window.getmaster.init(ssuccess,err);
```
