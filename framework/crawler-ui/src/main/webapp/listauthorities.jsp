<%@ include file="adminHeaders.jsp" %>

<%

/* $Id$ */

/**
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements. See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* 
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
%>

<%
try
{
  // Check if authorized
  if (!adminprofile.checkAllowed(threadContext,IAuthorizer.CAPABILITY_VIEW_CONNECTIONS))
  {
    variableContext.setParameter("target","index.jsp");
%>
    <jsp:forward page="unauthorized.jsp"/>
<%
  }
  // Get the authority connection manager handle
  IAuthorityConnectionManager manager = AuthorityConnectionManagerFactory.make(threadContext);
  IAuthorityConnectorManager connectorManager = AuthorityConnectorManagerFactory.make(threadContext);
  IAuthorityConnection[] connections = manager.getAllConnections();
%>

<script type="text/javascript">
  <!--
  $.ManifoldCF.setTitle(
      '<%=Messages.getBodyString(pageContext.getRequest().getLocale(), "listauthorities.ApacheManifoldCFListAuthorities")%>',
      '<%=Messages.getBodyString(pageContext.getRequest().getLocale(), "listauthorities.ListOfAuthorityConnections")%>',
      'authorities'
  );

  function Delete(connectionName)
  {
    if (confirm("<%=Messages.getBodyJavascriptString(pageContext.getRequest().getLocale(),"listauthorities.DeleteAuthority")%> '"+connectionName+"'?"))
    {
      document.listconnections.op.value="Delete";
      document.listconnections.connname.value=connectionName;
      document.listconnections.submit();
    }
  }

  //-->
</script>


<div class="row">
  <div class="col-md-12">
    <div class="box box-primary">
      <form class="standardform" name="listconnections" action="execute.jsp" method="POST">
        <input type="hidden" name="op" value="Continue"/>
        <input type="hidden" name="type" value="authority"/>
        <input type="hidden" name="connname" value=""/>

        <div class="box-body">
          <table class="table table-bordered">
            <tr>
              <th>Action</th>
              <th><%=Messages.getBodyString(pageContext.getRequest().getLocale(),"listauthorities.Name")%></th>
              <th><%=Messages.getBodyString(pageContext.getRequest().getLocale(),"listauthorities.Description")%></th>
              <th><%=Messages.getBodyString(pageContext.getRequest().getLocale(),"listauthorities.AuthorityType")%></th>
              <th><%=Messages.getBodyString(pageContext.getRequest().getLocale(),"listauthorities.Max")%></th>
            </tr>
<%
  int i = 0;
  while (i < connections.length)
  {
    IAuthorityConnection connection = connections[i++];

    String name = connection.getName();
    String description = connection.getDescription();
    if (description == null)
      description = "";
    String className = connection.getClassName();
    int maxCount = connection.getMaxConnections();
    String connectorName = connectorManager.getDescription(className);
    if (connectorName == null)
      connectorName = className + "(uninstalled)";

%>
            <tr>
              <td>
                <div class="btn-group">
                  <a href='<%="viewauthority.jsp?connname="+org.apache.manifoldcf.core.util.URLEncoder.encode(name)%>'
                          title='<%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.View") + " " +org.apache.manifoldcf.ui.util.Encoder.attributeEscape(name)%>'
                          class="link btn btn-success btn-xs" role="button" data-toggle="tooltip">
                    <i class="fa fa-eye fa-fw" aria-hidden="true"></i><%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.View")%></a>
                  <a href='<%="editauthority.jsp?connname="+org.apache.manifoldcf.core.util.URLEncoder.encode(name)%>'
                          title='<%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.Edit") + " " + org.apache.manifoldcf.ui.util.Encoder.attributeEscape(name)%>'
                          class="link btn btn-primary btn-xs" role="button" data-toggle="tooltip">
                    <i class="fa fa-pencil-square-o fa-fw" aria-hidden="true"></i><%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.Edit")%></a>
                  <a href="javascript:void(0);"
                          onclick='<%="javascript:Delete(\""+org.apache.manifoldcf.ui.util.Encoder.attributeJavascriptEscape(name)+"\")"%>'
                          title='<%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.Delete") + " " + org.apache.manifoldcf.ui.util.Encoder.attributeEscape(name)%>'
                          class="btn btn-danger btn-xs" role="button" data-toggle="tooltip">
                    <i class="fa fa-trash fa-fw" aria-hidden="true"></i><%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.Delete")%></a>
                </div>
              </td>
              <td><%=org.apache.manifoldcf.ui.util.Encoder.bodyEscape(name)%></td>
              <td><%=org.apache.manifoldcf.ui.util.Encoder.bodyEscape(description)%></td>
              <td><%=org.apache.manifoldcf.ui.util.Encoder.bodyEscape(connectorName)%></td>
              <td><%=Integer.toString(maxCount)%></td>
            </tr>
<%
  }
%>
          </table>
        </div>
        <div class="box-footer clearfix">
          <div class="btn-group">
            <a href="editauthority.jsp" title="<%=Messages.getAttributeString(pageContext.getRequest().getLocale(),"listauthorities.AddaNewConnection")%>"
                    class="link btn btn-primary" role="button">
              <i class="fa fa-plus-circle fa-fw" aria-hidden="true"></i><%=Messages.getBodyString(pageContext.getRequest().getLocale(),"listauthorities.AddNewConnection")%></a>
          </div>

<%
}
catch (ManifoldCFException e)
{
  e.printStackTrace();
  variableContext.setParameter("text",e.getMessage());
  variableContext.setParameter("target","index.jsp");
%>
  <jsp:forward page="error.jsp"/>
<%
}
%>
        </div>
      </form>
    </div>
  </div>
</div>
