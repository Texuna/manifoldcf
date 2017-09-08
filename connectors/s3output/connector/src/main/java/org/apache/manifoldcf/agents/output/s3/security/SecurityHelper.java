package org.apache.manifoldcf.agents.output.s3.security;

import org.apache.manifoldcf.agents.interfaces.IOutputAddActivity;
import org.apache.manifoldcf.agents.interfaces.RepositoryDocument;
import org.apache.manifoldcf.core.interfaces.ManifoldCFException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Created by jeckep on 08.09.17.
 */
public class SecurityHelper {

    public static Map<String, Security> getSecurityRules(RepositoryDocument document) throws ManifoldCFException {
        // Convert the incoming acls that we know about to qualified forms
        Map<String, Security> rules = new HashMap<>();

        Iterator<String> aclTypes = document.securityTypesIterator();
        while (aclTypes.hasNext()) {
            String aclType = aclTypes.next();
            rules.put(aclType, new Security(document.getSecurityACL(aclType), document.getSecurityDenyACL(aclType)));
        }
        return rules;
    }

    public static Map<String, Security> convertToSolrSecurityRules(Map<String, Security> rules, String authorityNameString, IOutputAddActivity activities) throws ManifoldCFException {
        Map<String, Security> solrRules = new HashMap<>();

        for(String aclType: rules.keySet()){
            String[] solrAllowTokens = convertACL(rules.get(aclType).getTokens(), authorityNameString, activities);
            String[] solrDenyTokens = convertACL(rules.get(aclType).getDenyTokens(), authorityNameString, activities);
            solrRules.put(aclType, new Security(solrAllowTokens, solrDenyTokens));
        }

        return solrRules;
    }

    /**
     * Convert an unqualified ACL to qualified form.
     *
     * @param acl                 is the initial, unqualified ACL.
     * @param authorityNameString is the name of the governing authority for this document's acls, or null if none.
     * @param activities          is the activities object, so we can report what's happening.
     * @return the modified ACL.
     */
    private static String[] convertACL(String[] acl, String authorityNameString, IOutputAddActivity activities) throws ManifoldCFException {
        if (acl != null) {
            String[] rval = new String[acl.length];
            int i = 0;
            while (i < rval.length) {
                rval[i] = activities.qualifyAccessToken(authorityNameString, acl[i]);
                i++;
            }
            return rval;
        }
        return new String[0];
    }
}
