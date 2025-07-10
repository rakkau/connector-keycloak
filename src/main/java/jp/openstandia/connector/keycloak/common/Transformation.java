package jp.openstandia.connector.keycloak.common;

import org.identityconnectors.common.logging.Log;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class    Transformation {

    private static final Log LOGGER = Log.getLog(Transformation.class);
    public static Map<String, List<RoleRepresentation>> groupsToClientRoleMap(List<String> roleList,
                                                                              String delimiter,
                                                                              Integer clientIndex,
                                                                              Integer groupIndex,
                                                                              RealmResource realm){
        Map<String, List<RoleRepresentation>> result = new HashMap<>();
        roleList.stream().forEach(r -> {
            String[] roleSplit = r.split(delimiter);
            String clientId = roleSplit[clientIndex];
            String roleName = roleSplit[groupIndex];
            if (roleSplit.length <= Math.max(clientIndex, groupIndex)) {
                LOGGER.warn("Invalid role format: " + r);
                return;
            }
            if(result.containsKey(clientId)){
                result.get(clientId).add(getClientRoleRepresentation(realm, clientId, roleName));
            }
            else {
                result.put(clientId, new ArrayList<RoleRepresentation>(){{add(getClientRoleRepresentation(realm, clientId, roleName));}});
            }
        });

        return result;
    }


    private static RoleRepresentation getClientRoleRepresentation(RealmResource realm, String clientId, String roleName){
        return realm.clients().get(clientId).roles().get(roleName).toRepresentation();
    }

}
