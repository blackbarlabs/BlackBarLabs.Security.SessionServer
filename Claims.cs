using System;
using System.Threading.Tasks;
using BlackBarLabs.Collections.Async;

namespace BlackBarLabs.Security.SessionServer
{
    public class Claims
    {
        private Context context;
        private Persistence.IDataContext dataContext;

        public async Task<TResult> FindAsync<TResult>(Guid authorizationId, Uri type,
            Func<IEnumerableAsync<Func<Guid, Guid, Uri, string, Task>>, TResult> found,
            Func<TResult> authorizationNotFound,
            Func<string, TResult> failure)
        {
            return await this.dataContext.Authorizations.UpdateClaims(authorizationId,
                (claimsStored, addClaim) =>
                {
                    var claims = EnumerableAsync.YieldAsync<Func<Guid, Guid, Uri, string, Task>>(
                        async (yieldAsync) =>
                        {
                            await claimsStored.ForAllAsync(
                                async (claimIdStorage, issuerStorage, typeStorage, valueStorage) =>
                                {
                                    if (default(Uri) == type ||
                                        String.Compare(type.AbsoluteUri, typeStorage.AbsoluteUri) == 0)
                                    {
                                        await yieldAsync(claimIdStorage, authorizationId, typeStorage, valueStorage);
                                    }
                                });
                        });
                    return Task.FromResult(found(claims));
                },
                // TODO: Create and use dataContext.Authorizations.FindClaims since next two methods are mute since addClaim is never invoked
                () => true,
                () => false,
                () => authorizationNotFound(),
                (whyFailed) => failure(whyFailed));
        }

        internal Claims(Context context, Persistence.IDataContext dataContext)
        {
            this.dataContext = dataContext;
            this.context = context;
        }

        public async Task<TResult> CreateAsync<TResult>(Guid claimId,
            Guid authorizationId, Uri issuer, Uri type, string value, string signature,
            Func<TResult> success,
            Func<TResult> authorizationNotFound,
            Func<TResult> alreadyExist,
            Func<string, TResult> failure)
        {
            return await this.dataContext.Authorizations.UpdateClaims<TResult, bool>(authorizationId,
                async (claimsStored, addClaim) =>
                {
                    bool existingClaimFound = false;
                    await claimsStored.ForAllAsync(
                        async (claimIdStorage, issuerStorage, typeStorage, valueStorage) =>
                        {
                            if (claimIdStorage == claimId)
                                existingClaimFound = true;
                            await Task.FromResult(true);
                        });
                    if (existingClaimFound)
                        return alreadyExist();

                    var successAddingClaim = await addClaim(claimId, issuer, type, value);
                    if (successAddingClaim)
                        return success();

                    return failure("Could not add claim");
                },
                () => true,
                () => false,
                () => authorizationNotFound(),
                (whyFailed) => failure(whyFailed));
        }

        public async Task<TResult> UpdateAsync<TResult>(Guid claimId,
            Guid authorizationId, Uri issuer, Uri type, string value, string signature,
            Func<TResult> success,
            Func<TResult> authorizationNotFound,
            Func<TResult> claimNotFound,
            Func<string, TResult> failure)
        {
            return await this.dataContext.Authorizations.UpdateClaims<TResult, bool>(authorizationId,
                async (claimsStored, addClaim) =>
                {
                    bool existingClaimFound = false;
                    await claimsStored.ForAllAsync(
                        async (claimIdStorage, issuerStorage, typeStorage, valueStorage) =>
                        {
                            if (claimIdStorage == claimId)
                                existingClaimFound = true;
                            await Task.FromResult(true);
                        });
                    if (!existingClaimFound)
                        return claimNotFound();

                    var successAddingClaim = await addClaim(claimId, issuer, type, value);
                    if (successAddingClaim)
                        return success();

                    return failure("Could not add claim");
                },
                () => true,
                () => false,
                () => authorizationNotFound(),
                (whyFailed) => failure(whyFailed));
        }
    }
}
