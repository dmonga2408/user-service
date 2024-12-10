# user-service

Time spent - 1.5 hours

This is an authorization server based on spring oauth2-authorization-server
This can provide and support different OAuth2.1 flows
A sample test is added AuthTokenEndpointTest which can make a call
to token endpoint /oaut2/token and fetch a token using Reactive WebClient

- This Authorization server will be invoked from the BFF using 
- Authorization_Code grant which will return a token for given code
- Client receives the token from the user login page redirect after user is authenticated with the credentials


USER ( UI) -> Login with username/password -> Redirect to BFF endpoint with a code -> BFF calling authorizatio server oauth2/token endpoint to exchange the token for the opaque access token -> This token is passed to the auction service -> Auction service introspects the token for different scopes and provides access to different endpoints based on the authorities assigned to the user
