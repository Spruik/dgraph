package openIdConnect

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/dgraph/schema"
	"github.com/dgraph-io/dgraph/x"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/metadata"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

type Token struct {
	Upgraded         *bool    `json:"upgraded"`
	AccessToken      *string  `json:"access_token"`
	ExpiresIn        *float64 `json:"expires_in"`
	RefreshExpiresIn *float64 `json:"refresh_expires_in"`
	RefreshToken     *string  `json:"refresh_token"`
	TokenType        *string  `json:"token_type"`
	NotBeforePolicy  *float64 `json:"not-before-policy"`
	Error            *string  `json:"error"`
	ErrorDescription *string  `json:"error-description"`
}

/* Policy Enforcement Point (PEP) is the generic term given to the code within an application
that checks the user's permissions against the resource and scope being accessed.
In UserManagedAccess (UMA), checking for permissions is separated from authentication.

*/
// a global variable to hold the PEP keys and configuration
var OidcPep *PEP

type PEP struct {
	rsaKeys      map[string]*rsa.PublicKey
	baseUrl      string
	realm        string
	clientId     string
	clientSecret string
}

/* Create a new instance of the Policy Enforcement Point, and request the public keys from the authorization server */
func NewPEP() (*PEP, error) {
	pep := PEP{
		baseUrl:      x.Config.OIDC.GetString("url"),
		realm:        x.Config.OIDC.GetString("realm"),
		clientSecret: x.Config.OIDC.GetString("client-secret"),
		clientId:     x.Config.OIDC.GetString("client-id"),
	}
	err := pep.GetPublicKeys()
	return &pep, err
}

/* In order to validate JWTs, the public keys of the server are required.
These can be retrieved from the OAuth2 server
*/
func (pep *PEP) GetPublicKeys() error {
	pep.rsaKeys = make(map[string]*rsa.PublicKey)
	var body map[string]interface{}
	uri := pep.baseUrl + "/realms/" + pep.realm + "/protocol/openid-connect/certs"
	glog.Infof("getting oidc public keys from %s", uri)
	resp, err := http.Get(uri)
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return err
	}
	glog.Infof("%s", body)
	for _, bodyKey := range body["keys"].([]interface{}) {
		key := bodyKey.(map[string]interface{})
		kid := key["kid"].(string)
		rsaKey := new(rsa.PublicKey)
		number, err := base64.RawURLEncoding.DecodeString(key["n"].(string))
		if err != nil {
			return err
		}
		rsaKey.N = new(big.Int).SetBytes(number)
		rsaKey.E = 65537
		pep.rsaKeys[kid] = rsaKey
	}
	return nil
}

/* The Requesting Party Token (RPT) is a special JWT that contains
the permissions and scopes for authorization. To get an RPT, pass in the access token
of the user, and the resource and client that the user is trying to access.
*/
func (pep *PEP) GetRPT(accessToken, resource string) (*string, error) {
	// check that the accessToken is valid
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return pep.rsaKeys[token.Header["kid"].(string)], nil
	}, jwt.WithoutAudienceValidation())
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("access Token is invalid")
	}
	client := http.Client{}
	authUrl := pep.baseUrl + "/realms/" + pep.realm + "/protocol/openid-connect/token"
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Add("permission", resource)
	form.Add("audience", pep.clientId)

	req, err := http.NewRequest(http.MethodPost, authUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		glog.Info(err)
		return nil, err
	}
	response := Token{}
	err = json.Unmarshal(resBody, &response)
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		// an error was returned
		glog.Errorf("Error %v Description %v", *response.Error, response.ErrorDescription)
		return nil, errors.New(fmt.Sprintf("Error %v Description %v", *response.Error, response.ErrorDescription))
	}
	return response.AccessToken, nil
}

/* Use the Requesting Party Token (RPT) and the list of types to check if the
user has permission to access the types in the request
*/
func (pep *PEP) CheckPermission(operationType string, ctx context.Context, typeList map[string]string) error {
	// ToDo: Check the Authorization here
	// Get the list of types from the query and check against the auth.
	md, _ := metadata.FromIncomingContext(ctx)
	jwtTokens := md.Get("auth-token")
	if len(jwtTokens) < 1 {
		return errors.New("no access token provided")
	}
	jwtToken, err := stripBearerPrefixFromTokenString(jwtTokens[0])
	if err != nil {
		glog.Error(err)
		return err
	}
	// check the jwt. We expect the auth-token to be a bearer token, so we need to
	// strip off the "bearer "
	_, err = jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return pep.rsaKeys[token.Header["kid"].(string)], nil
	}, jwt.WithAudience(pep.clientId))
	if err != nil {
		glog.Error(err)
		return err
	}
	rpt, err := pep.GetRPT(jwtToken, "graphql")
	if err != nil {
		glog.Error(err)
		return err
	}
	// get the claims from the RPT
	claims, err := pep.ValidateAndDecodeRPT(*rpt)
	if err != nil {
		return err
	}
	// get the permission scopes from the RPT claims
	scopes := pep.ExtractAuthVariablesFromClaims(claims)
	authorized := true
	errorDescription := ""
	for typeName := range typeList {
		// skip over any of the standard types that start with __
		if strings.HasPrefix(typeName, "__") {
			continue
		}
		// Ignore built-in type names
		switch typeName {
		case
			"Point",
			"Polygon",
			"MultiPolygon":
			continue
		}
		if _, ok := scopes[typeName+":"+operationType]; !ok {
			authorized = false
			errorDescription = errorDescription + " unauthorized type " + typeName
		}
	}
	if !authorized {
		return errors.New(errorDescription)
	}
	return nil
}
func (pep *PEP) GetCustomClaims(ctx context.Context) (*CustomClaims, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	jwtTokens := md.Get("auth-token")
	if len(jwtTokens) < 1 {
		return nil, errors.New("no access token provided")
	}
	jwtToken, err := stripBearerPrefixFromTokenString(jwtTokens[0])
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	// check the jwt. We expect the auth-token to be a bearer token, so we need to
	// strip off the "bearer "
	_, err = jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return pep.rsaKeys[token.Header["kid"].(string)], nil
	}, jwt.WithAudience(pep.clientId))
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	rpt, err := pep.GetRPT(jwtToken, "graphql")
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	// get the claims from the RPT
	claims, err := pep.ValidateAndDecodeRPT(*rpt)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

/* Use the Requesting Party Token (RPT) and the list of types to check if the
user has permission to access the types in the request
*/
func (pep *PEP) CheckAdminPermission(token string) error {

	// check the jwt
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return pep.rsaKeys[token.Header["kid"].(string)], nil
	})
	rpt, err := pep.GetRPT(token, "admin")
	if err != nil {
		glog.Info(err)
		return err
	}
	// get the claims from the RPT
	claims, err := pep.ValidateAndDecodeRPT(*rpt)
	if err != nil {
		return err
	}

	authorized := false
	errorDescription := "token does not have permission to access the admin scope on the admin resource"

	for _, scope := range pep.ExtractAuthVariablesFromClaims(claims) {
		if scope == "admin" {
			authorized = true
			break
		}
	}

	if !authorized {
		return errors.New(errorDescription)
	}
	return nil
}

type CustomClaims struct {
	AuthVariables struct {
		Permissions []struct {
			Scopes []string `json:"scopes"`
		} `json:"permissions"`
	} `json:"authorization"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		LibreBaas struct {
			Roles []string `json:"roles"`
		} `json:"libreBaas"`
	} `json:"resource_access"`
	jwt.StandardClaims
	Name  string `json:"name"`
	Email string `json:"email"`
}

/* The Requesting Party Token (RPT) is a special JWT that contains
the permissions and scopes for authorization. To get an RPT, pass in the access token
of the user, and the resource and client that the user is trying to access.
The authorization scopes are held within the claim authorization.permissions.scopes
*/
func (pep *PEP) ValidateAndDecodeRPT(RPT string) (*CustomClaims, error) {

	token, err := jwt.ParseWithClaims(RPT, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pep.rsaKeys[token.Header["kid"].(string)], nil
	}, jwt.WithoutAudienceValidation())
	if err != nil {
		return nil, err
	}

	if token.Valid {
		return token.Claims.(*CustomClaims), nil
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}
	return nil, err
}

func (pep *PEP) ExtractAuthVariablesFromClaims(claims *CustomClaims) map[string]interface{} {

	customClaims := make(map[string]interface{})

	customClaims["name"] = claims.Name
	customClaims["email"] = claims.Email
	// add the jwt standard claims
	customClaims["sub"] = claims.Subject
	customClaims["exp"] = claims.ExpiresAt
	customClaims["iat"] = claims.IssuedAt
	customClaims["iss"] = claims.Issuer
	customClaims["nbf"] = claims.NotBefore
	// map the permissions claim from the token
	if len(claims.AuthVariables.Permissions) > 0 {
		for _, permission := range claims.AuthVariables.Permissions {
			if len(permission.Scopes) > 0 {
				for _, scope := range permission.Scopes {
					customClaims[scope] = scope
				}
			}
		}
	}
	// map the realm_access roles from the token
	if len(claims.RealmAccess.Roles) > 0 {
		customClaims["realm_access.roles"] = strings.Join(claims.RealmAccess.Roles, ",")
	}
	// map the resource_access roles for the libreBaas client from the token if it exists
	if len(claims.ResourceAccess.LibreBaas.Roles) > 0 {
		customClaims["resource_access.libreBaas.roles"] = strings.Join(claims.ResourceAccess.LibreBaas.Roles, ",")
	}

	return customClaims
}

/*
Sync OIDC Resource updates the Authorization Resource Scopes in the Authorization Server
to match the list of types in the schema. For each type in the schema we create query, mutation and subscription scopes
The flow is as follows:
- request an access token using the client system account.
- use the access token to query the client for the resource by name. If it exists, we update otherwise we create
- update the resource definition in the authorization server.
ToDo: Extend this section to self-register a client for this server
*/
func (pep *PEP) SyncOIDCGraphQLResource(ctx context.Context, schema *schema.ParsedSchema) error {
	token, err := pep.GetAccessToken()
	if err != nil {
		return err
	}
	resourceId, err := pep.QueryResource("graphql", *token)
	if err != nil {
		return err
	}
	// If the resourceId is nil, a new resource will be created, otherwise the existing resource will be updated
	return pep.UpdateAuthResourceDefinition(ctx, schema, *token, resourceId)
}
func (pep *PEP) SyncOIDCAdminResource(ctx context.Context) error {
	token, err := pep.GetAccessToken()
	if err != nil {
		return err
	}
	resourceId, err := pep.QueryResource("admin", *token)
	if err != nil {
		return err
	}
	// If the resourceId is nil, a new resource will be created, otherwise the existing resource will be updated
	return pep.UpdateAuthAdminResourceDefinition(ctx, *token, resourceId)
}

/* Get Access Token uses the client system account to get an access token
using the client_id and client_secret
*/
func (pep *PEP) GetAccessToken() (*string, error) {

	client := http.Client{}
	authUrl := pep.baseUrl + "/realms/" + pep.realm + "/protocol/openid-connect/token"
	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req, err := http.NewRequest(http.MethodPost, authUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(pep.clientId, pep.clientSecret)
	glog.Infof("getting access tokens %s", *req)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	response := Token{}
	err = json.Unmarshal(resBody, &response)
	if err != nil {
		return nil, err
	}
	glog.Infof("access token received: accessToken %s", response)
	if response.Error != nil {
		// an error was returned
		glog.Errorf("Error %v ", *response.Error)
		return nil, errors.New(fmt.Sprintf("Error %v Description %v", *response.Error, *response.ErrorDescription))
	}
	if response.AccessToken != nil {
		return response.AccessToken, nil
	}
	return nil, nil
}

/* query the authorization server for a resource name.
If it exists, the resourceId will be returned
*/
func (pep *PEP) QueryResource(name, token string) (*string, error) {

	client := http.Client{}
	authUrl := pep.baseUrl + "/realms/" + pep.realm + "/authz/protection/resource_set?name=" + name

	req, err := http.NewRequest(http.MethodGet, authUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	glog.Infof("query resource :%s", *req)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		var respError map[string]interface{}
		err = json.Unmarshal(resBody, &respError)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(respError["error"].(string) + " " + respError["error_description"].(string))
	}
	var response []string

	err = json.Unmarshal(resBody, &response)
	if err != nil {
		return nil, err
	}
	glog.Info(cmp.Diff(nil, response))
	if len(response) > 0 {
		return &response[0], nil
	}

	return nil, nil
}

type ResourceDefinition struct {
	Name           string   `json:"name"`
	ResourceScopes []string `json:"resource_scopes"`
}

func (pep *PEP) UpdateAuthResourceDefinition(ctx context.Context, schema *schema.ParsedSchema, token string, resourceId *string) error {
	resourceDefinition := ResourceDefinition{Name: "graphql"}
	for _, update := range schema.Types {
		resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, strings.Trim(update.TypeName, "\000")+":query")
		resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, strings.Trim(update.TypeName, "\000")+":mutation")
		resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, strings.Trim(update.TypeName, "\000")+":subscription")
		resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, strings.Trim(update.TypeName, "\000")+":delete")
	}
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "GQLSchema:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "NodeState:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "MembershipState:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "ClusterGroup:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "Member:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "Tablet:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "License:query")
	jsonBody, err := json.Marshal(resourceDefinition)
	if err != nil {
		return err
	}
	glog.Info(string(jsonBody))

	client := http.Client{}
	authUrl := pep.baseUrl + "/realms/" + pep.realm + "/authz/protection/resource_set"
	method := http.MethodPost
	if resourceId != nil {
		authUrl += "/" + *resourceId
		method = http.MethodPut
	}

	req, err := http.NewRequest(method, authUrl, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	glog.Info(cmp.Diff(nil, req))
	res, err := client.Do(req)
	if err != nil {
		glog.Error(err)
		return err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		glog.Error(err)
		return err
	}

	glog.Info(cmp.Diff(nil, string(resBody)))

	return nil
}

func (pep *PEP) UpdateAuthAdminResourceDefinition(ctx context.Context, token string, resourceId *string) error {
	resourceDefinition := ResourceDefinition{
		Name: "admin",
	}
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "admin")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "GQLSchema:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "NodeState:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "MembershipState:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "ClusterGroup:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "Member:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "Tablet:query")
	resourceDefinition.ResourceScopes = append(resourceDefinition.ResourceScopes, "License:query")

	jsonBody, err := json.Marshal(resourceDefinition)
	if err != nil {
		return err
	}
	glog.Info(string(jsonBody))

	client := http.Client{}
	authUrl := pep.baseUrl + "/realms/" + pep.realm + "/authz/protection/resource_set"
	method := http.MethodPost
	if resourceId != nil {
		authUrl += "/" + *resourceId
		method = http.MethodPut
	}

	req, err := http.NewRequest(method, authUrl, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		glog.Error(err)
		return err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		glog.Error(err)
		return err
	}

	glog.Info(cmp.Diff(nil, string(resBody)))

	return nil
}

// Strips 'Bearer ' prefix from bearer token string
func stripBearerPrefixFromTokenString(tok string) (string, error) {
	// Should be a bearer token
	if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
		return tok[7:], nil
	}
	return tok, nil
}
