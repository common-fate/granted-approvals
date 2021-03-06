package identitysync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/common-fate/granted-approvals/pkg/deploy"
	"github.com/common-fate/granted-approvals/pkg/identity"
)

const MSGraphBaseURL = "https://graph.microsoft.com/v1.0"
const ADAuthorityHost = "https://login.microsoftonline.com"

type AzureSync struct {
	NewClient *http.Client
	token     string
}

type ListUsersResponse struct {
	OdataContext  string      `json:"@odata.context"`
	OdataNextLink *string     `json:"@odata.nextLink,omitempty"`
	Value         []AzureUser `json:"value"`
}

// properties of a user in the graph API
//
// https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
type AzureUser struct {
	GivenName string `json:"givenName"`
	// this maps to a users email by convention
	// see the graph API spec for details
	// in practive all users have a principal name but some users may not have the "mail" property for different reasons.
	// we use this for the email
	UserPrincipalName string `json:"userPrincipalName"`
	Surname           string `json:"surname"`
	ID                string `json:"id"`
}

type ListGroupsResponse struct {
	OdataContext  string       `json:"@odata.context"`
	OdataNextLink *string      `json:"@odata.nextLink,omitempty"`
	Value         []AzureGroup `json:"value"`
}

type AzureGroup struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	DisplayName string `json:"displayName"`
}

type UserGroups struct {
	OdataNextLink *string  `json:"@odata.nextLink,omitempty"`
	OdataContext  string   `json:"@odata.context"`
	Value         []string `json:"value"`
}

type ClientSecretCredential struct {
	client confidential.Client
}

// GetToken requests an access token from Azure Active Directory. This method is called automatically by Azure SDK clients.
func (c *ClientSecretCredential) GetToken(ctx context.Context) (string, error) {
	ar, err := c.client.AcquireTokenByCredential(ctx, []string{"https://graph.microsoft.com/.default"})
	return ar.AccessToken, err
}

func NewClientSecretCredential(s deploy.Azure, httpClient *http.Client) (*ClientSecretCredential, error) {
	cred, err := confidential.NewCredFromSecret(s.ClientSecret)
	if err != nil {
		return nil, err
	}
	c, err := confidential.New(s.ClientID, cred,
		confidential.WithAuthority(fmt.Sprintf("%s/%s", ADAuthorityHost, s.TenantID)),
		confidential.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	return &ClientSecretCredential{client: c}, nil
}

// NewAzure will fail if the Azure settings are not configured
func NewAzure(ctx context.Context, settings deploy.Azure) (*AzureSync, error) {
	azAuth, err := NewClientSecretCredential(settings, http.DefaultClient)
	if err != nil {
		return nil, err
	}
	token, err := azAuth.GetToken(ctx)
	if err != nil {
		return nil, err
	}

	return &AzureSync{NewClient: http.DefaultClient, token: token}, nil
}

// idpUserFromAzureUser converts a azure user to the identityprovider interface user type
func (a *AzureSync) idpUserFromAzureUser(ctx context.Context, azureUser AzureUser) (identity.IdpUser, error) {
	u := identity.IdpUser{
		ID:        azureUser.ID,
		FirstName: azureUser.GivenName,
		LastName:  azureUser.Surname,
		Email:     azureUser.UserPrincipalName,
		Groups:    []string{},
	}

	g, err := a.GetMemberGroups(u.ID)
	if err != nil {
		return identity.IdpUser{}, err
	}
	u.Groups = g

	return u, nil
}

func (a *AzureSync) GetMemberGroups(userID string) ([]string, error) {
	var userGroups []string

	hasMore := true
	var nextToken *string
	url := MSGraphBaseURL + fmt.Sprintf("/directoryObjects/%s/getMemberGroups", userID)

	for hasMore {
		var jsonStr = []byte(`{ "securityEnabledOnly": false}`)
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
		req.Header.Add("Authorization", "Bearer "+a.token)
		req.Header.Set("Content-Type", "application/json")

		res, err := a.NewClient.Do(req)
		if err != nil {
			return nil, err
		}

		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		//return the error if its anything but a 200
		if res.StatusCode != 200 {
			return nil, fmt.Errorf(string(b))
		}

		var lu UserGroups
		err = json.Unmarshal(b, &lu)
		if err != nil {
			return nil, err
		}

		userGroups = append(userGroups, lu.Value...)

		nextToken = lu.OdataNextLink
		if nextToken != nil {
			url = *nextToken
		} else {
			hasMore = false
		}

	}
	return userGroups, nil
}

func (a *AzureSync) ListUsers(ctx context.Context) ([]identity.IdpUser, error) {

	//get all users
	idpUsers := []identity.IdpUser{}
	hasMore := true
	var nextToken *string
	url := MSGraphBaseURL + "/users"

	for hasMore {

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Add("Authorization", "Bearer "+a.token)
		res, err := a.NewClient.Do(req)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		//return the error if its anything but a 200
		if res.StatusCode != 200 {
			return nil, fmt.Errorf(string(b))
		}

		var lu ListUsersResponse
		err = json.Unmarshal(b, &lu)
		if err != nil {
			return nil, err
		}

		for _, u := range lu.Value {

			user, err := a.idpUserFromAzureUser(ctx, u)
			if err != nil {
				return nil, err
			}
			idpUsers = append(idpUsers, user)
		}
		nextToken = lu.OdataNextLink
		if nextToken != nil {
			url = *nextToken
		} else {
			hasMore = false
		}

	}

	return idpUsers, nil
}

// idpGroupFromAzureGroup converts a azure group to the identityprovider interface group type
func idpGroupFromAzureGroup(azureGroup AzureGroup) identity.IdpGroup {
	return identity.IdpGroup{
		ID:          azureGroup.ID,
		Name:        azureGroup.DisplayName,
		Description: string(azureGroup.Description),
	}
}
func (a *AzureSync) ListGroups(ctx context.Context) ([]identity.IdpGroup, error) {
	idpGroups := []identity.IdpGroup{}
	hasMore := true
	var nextToken *string
	url := MSGraphBaseURL + "/groups"
	for hasMore {

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Add("Authorization", "Bearer "+a.token)
		res, err := a.NewClient.Do(req)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		//return the error if its anything but a 200
		if res.StatusCode != 200 {
			return nil, fmt.Errorf(string(b))
		}

		var lu ListGroupsResponse
		err = json.Unmarshal(b, &lu)
		if err != nil {
			return nil, err
		}

		for _, u := range lu.Value {

			group := idpGroupFromAzureGroup(u)
			if err != nil {
				return nil, err
			}
			idpGroups = append(idpGroups, group)
		}
		nextToken = lu.OdataNextLink
		if nextToken != nil {
			url = *nextToken
		} else {
			hasMore = false
		}
	}
	return idpGroups, nil
}
