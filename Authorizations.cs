using System;
using System.Threading.Tasks;
using BlackBarLabs.Security.Session;

namespace BlackBarLabs.Security.SessionServer
{
    public class Authorizations
    {
        private Context context;

        private Persistence.IDataContext dataContext;

        internal Authorizations(Context context, Persistence.IDataContext dataContext)
        {
            this.dataContext = dataContext;
            this.context = context;
        }
        
        #region Credentials
        
        public async Task<TResult> CreateAsync<TResult>(Guid authorizationId, Func<TResult> onSuccess, Func<TResult> onAlreadyExists)
        {
            var result = await this.dataContext.Authorizations.CreateAuthorizationAsync(authorizationId,
                () => onSuccess(),
                () => onAlreadyExists());
            return result;
        }

        

        public async Task<TResult> CreateCredentialsAsync<TResult>(Guid authorizationId, 
            CredentialValidationMethodTypes method, Uri providerId, string username, string token,
            Func<TResult> success, Func<TResult> authenticationFailed,
            Func<TResult> authorizationDoesNotExists,
            Func<Guid, TResult> alreadyAssociated)
        {
            // ... validates the provider credentials before accepting / storing them.
            var provider = this.context.GetCredentialProvider(method);
            var result = await await provider.RedeemTokenAsync(providerId, username, token,
                async (resultToken) =>
                {
                    return await this.dataContext.Authorizations.CreateCredentialProviderAsync(authorizationId,
                        providerId, username,
                        () => success(),
                        () => authorizationDoesNotExists(),
                        (alreadyAssociatedAuthorizationId) => alreadyAssociated(alreadyAssociatedAuthorizationId));
                },
                (errorMessage) => Task.FromResult(authenticationFailed()),
                () => Task.FromResult(default(TResult)));
            return result;
            }

        public async Task<TResult> GetCredentialsAsync<TResult>(CredentialValidationMethodTypes method, Uri providerId, string username,
            Func<Guid, TResult> success,
            Func<TResult> authorizationDoesNotExists)
        {
            var provider = this.context.GetCredentialProvider(method);
            return
                await
                    provider.GetCredentialsAsync<TResult>(providerId, username,
                        s => success(Guid.Parse(s)),
                        authorizationDoesNotExists);
        }


        public async Task<TResult> UpdateCredentialsAsync<TResult>(Guid authorizationId,
            CredentialValidationMethodTypes method, Uri providerId, string username, string token,
            Func<TResult> success, 
            Func<TResult> authorizationDoesNotExists,
            Func<TResult> updateFailed)
        {
            //Updates the Credential Password
            var provider = this.context.GetCredentialProvider(method);
            var result = await await provider.UpdateTokenAsync(providerId, username, token,
                (returnToken) => Task.FromResult(success()),
                async () =>
                {
                    if (method != CredentialValidationMethodTypes.Implicit)
                        return authorizationDoesNotExists();
                    return await CreateCredentialsAsync(authorizationId, 
                        method, providerId, username, token,
                        success,
                        updateFailed,
                        authorizationDoesNotExists,
                        (authIdExists) => updateFailed());
                },
                () => Task.FromResult(updateFailed()));
            return result;
        }


        #endregion

    }
}
