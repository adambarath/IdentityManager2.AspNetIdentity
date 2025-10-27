using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityManager2.Core;
using IdentityManager2.Core.Metadata;
using IdentityManager2.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityManager2.AspNetIdentity
{
    public class AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey> : IIdentityManagerService
        where TUser : IdentityUser<TUserKey>, new()
        where TRole : IdentityRole<TRoleKey>, new()
        where TUserKey : IEquatable<TUserKey>
        where TRoleKey : IEquatable<TRoleKey>
    {
        public string RoleClaimType { get; set; }

        protected readonly ILogger logger;
        protected readonly UserManager<TUser> UserManager;
        protected readonly RoleManager<TRole> RoleManager;
        protected readonly Func<Task<IdentityManagerMetadata>> MetadataFunc;

        #region Constructors

        internal AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            ILogger<AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey>> logger
        )
        {
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this.RoleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));

            logger.LogInformation("Initializing AspNetCoreIdentityManagerService with UserManager: {UserManagerType}, RoleManager: {RoleManagerType}",
                typeof(TUser).Name, typeof(TRole).Name);

            if (!userManager.SupportsQueryableUsers)
            {
                logger.LogError("UserManager does not support queryable users");
                throw new InvalidOperationException("UserManager must support queryable users.");
            }

            var email = userManager.Options.Tokens.EmailConfirmationTokenProvider; // TODO: and for rest...
            if (!userManager.Options.Tokens.ProviderMap.ContainsKey(email))
            {
                logger.LogWarning("Email token provider '{EmailProvider}' not found in token provider map", email);
            }

            RoleClaimType = IdentityManagerConstants.ClaimTypes.Role;
            logger.LogDebug("RoleClaimType set to: {RoleClaimType}", RoleClaimType);
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            ILogger<AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey>> logger,
            bool includeAccountProperties = true
        )
            : this(userManager, roleManager, logger)
        {
            logger.LogDebug("Using standard metadata with includeAccountProperties: {IncludeAccountProperties}", includeAccountProperties);
            MetadataFunc = () => GetStandardMetadata(includeAccountProperties);
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            IdentityManagerMetadata metadata,
            ILogger<AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey>> logger
        )
            : this(userManager, roleManager, () => Task.FromResult(metadata), logger)
        {
            logger.LogDebug("Using custom metadata");
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            Func<Task<IdentityManagerMetadata>> metadataFunc,
            ILogger<AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey>> logger)
            : this(userManager, roleManager, logger)
        {
            this.MetadataFunc = metadataFunc;
            logger.LogDebug("Using custom metadata function");
        }

        #endregion

        public Task<IdentityManagerMetadata> GetMetadataAsync()
        {
            logger.LogDebug("Getting metadata");
            return MetadataFunc();
        }

        public async Task<IdentityManagerResult<CreateResult>> CreateUserAsync(IEnumerable<PropertyValue> properties)
        {
            logger.LogInformation("Creating new user");

            var usernameClaim = properties.Single(x => x.Type == IdentityManagerConstants.ClaimTypes.Username);
            var passwordClaim = properties.Single(x => x.Type == IdentityManagerConstants.ClaimTypes.Password);

            var username = usernameClaim.Value;
            var password = passwordClaim.Value;

            logger.LogDebug("Creating user with username: {Username}", username);

            var exclude = new[] { IdentityManagerConstants.ClaimTypes.Username, IdentityManagerConstants.ClaimTypes.Password };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            if (otherProperties.Any())
            {
                logger.LogDebug("Creating user with {PropertyCount} additional properties", otherProperties.Length);
            }

            var metadata = await GetMetadataAsync();
            var createProps = metadata.UserMetadata.GetCreateProperties();

            var user = new TUser { UserName = username };
            foreach (var prop in otherProperties)
            {
                logger.LogDebug("Setting user property: {PropertyType} for username: {Username}", prop.Type, username);
                var propertyResult = await SetUserProperty(createProps, user, prop.Type, prop.Value);
                if (!propertyResult.IsSuccess)
                {
                    logger.LogWarning("Failed to set user property {PropertyType} for username {Username}: {Errors}",
                        prop.Type, username, string.Join(", ", propertyResult.Errors));
                    return new IdentityManagerResult<CreateResult>(propertyResult.Errors.ToArray());
                }
            }

            var result = await UserManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to create user {Username}: {Errors}",
                    username, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully created user {Username} with ID: {UserId}", username, user.Id);
            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = user.Id.ToString() });
        }

        public async Task<IdentityManagerResult> DeleteUserAsync(string subject)
        {
            logger.LogInformation("Deleting user with subject: {Subject}", subject);

            var user = await UserManager.FindByIdAsync(subject);
            if (user == null)
            {
                logger.LogWarning("User not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Found user {Username} (ID: {UserId}) for deletion", user.UserName, user.Id);

            var result = await UserManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to delete user {Username} (ID: {UserId}): {Errors}",
                    user.UserName, user.Id, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully deleted user {Username} (ID: {UserId})", user.UserName, user.Id);
            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync(string filter, int start, int count)
        {
            logger.LogInformation("Querying users with filter: '{Filter}', start: {Start}, count: {Count}", filter ?? "(none)", start, count);

            var query =
                from user in UserManager.Users
                orderby user.UserName
                select user;

            if (!string.IsNullOrWhiteSpace(filter))
            {
                query =
                    from user in query
                    where user.UserName.Contains(filter)
                    orderby user.UserName
                    select user;
            }

            var total = query.Count();
            var users = query.Skip(start).Take(count).ToArray();

            logger.LogDebug("Query returned {ResultCount} users out of {TotalCount} total", users.Length, total);

            var items = new List<UserSummary>();
            foreach (var user in users)
            {
                items.Add(new UserSummary
                {
                    Subject = user.Id.ToString(),
                    Username = user.UserName,
                    Name = await DisplayNameFromUser(user)
                });
            }

            var result = new QueryResult<UserSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter,
                Items = items
            };

            logger.LogInformation("Successfully queried users: returned {ResultCount} users", items.Count);
            return new IdentityManagerResult<QueryResult<UserSummary>>(result);
        }

        public async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string subject)
        {
            logger.LogInformation("Getting user details for subject: {Subject}", subject);

            var user = await UserManager.FindByIdAsync(subject);
            if (user == null)
            {
                logger.LogWarning("User not found with subject: {Subject}", subject);
                return new IdentityManagerResult<UserDetail>((UserDetail)null);
            }

            logger.LogDebug("Found user {Username} (ID: {UserId})", user.UserName, user.Id);

            var result = new UserDetail
            {
                Subject = subject,
                Username = user.UserName,
                Name = await DisplayNameFromUser(user),
            };

            var metadata = await GetMetadataAsync();

            var props = new List<PropertyValue>();
            foreach (var prop in metadata.UserMetadata.UpdateProperties)
            {
                props.Add(new PropertyValue
                {
                    Type = prop.Type,
                    Value = await GetUserProperty(prop, user)
                });
            }

            result.Properties = props.ToArray();
            logger.LogDebug("Retrieved {PropertyCount} properties for user {Username}", props.Count, user.UserName);

            if (UserManager.SupportsUserClaim)
            {
                var userClaims = await UserManager.GetClaimsAsync(user);
                var claims = new List<ClaimValue>();
                if (userClaims != null)
                {
                    claims.AddRange(userClaims.Select(x => new ClaimValue { Type = x.Type, Value = x.Value }));
                }
                result.Claims = claims.ToArray();
                logger.LogDebug("Retrieved {ClaimCount} claims for user {Username}", claims.Count, user.UserName);
            }

            logger.LogInformation("Successfully retrieved details for user {Username}", user.UserName);
            return new IdentityManagerResult<UserDetail>(result);
        }

        public async Task<IdentityManagerResult> SetUserPropertyAsync(string subject, string type, string value)
        {
            logger.LogInformation("Setting user property {PropertyType} for subject: {Subject}", type, subject);

            var user = await UserManager.FindByIdAsync(subject);
            if (user == null)
            {
                logger.LogWarning("User not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Setting property {PropertyType} to value '{Value}' for user {Username}", type, value, user.UserName);

            var errors = ValidateUserProperty(type, value).ToList();
            if (errors.Any())
            {
                logger.LogWarning("Validation failed for user property {PropertyType}: {Errors}", type, string.Join(", ", errors));
                return new IdentityManagerResult(errors.ToArray());
            }

            var metadata = await GetMetadataAsync();
            var propResult = await SetUserProperty(metadata.UserMetadata.UpdateProperties, user, type, value);
            if (!propResult.IsSuccess)
            {
                logger.LogWarning("Failed to set user property {PropertyType} for user {Username}: {Errors}",
                    type, user.UserName, string.Join(", ", propResult.Errors));
                return propResult;
            }

            var result = await UserManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to update user {Username} after setting property {PropertyType}: {Errors}",
                    user.UserName, type, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully set property {PropertyType} for user {Username}", type, user.UserName);
            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> AddUserClaimAsync(string subject, string type, string value)
        {
            logger.LogInformation("Adding claim {ClaimType} to user with subject: {Subject}", type, subject);

            var user = await UserManager.FindByIdAsync(subject);
            if (user == null)
            {
                logger.LogWarning("User not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Adding claim {ClaimType} with value '{ClaimValue}' to user {Username}", type, value, user.UserName);

            var existingClaims = await UserManager.GetClaimsAsync(user);
            if (!existingClaims.Any(x => x.Type == type && x.Value == value))
            {
                var result = await UserManager.AddClaimAsync(user, new Claim(type, value));
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed to add claim {ClaimType} to user {Username}: {Errors}",
                        type, user.UserName, string.Join(", ", result.Errors.Select(x => x.Description)));
                    return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
                }
                logger.LogInformation("Successfully added claim {ClaimType} to user {Username}", type, user.UserName);
            }
            else
            {
                logger.LogDebug("Claim {ClaimType} with value '{ClaimValue}' already exists for user {Username}", type, value, user.UserName);
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> RemoveUserClaimAsync(string subject, string type, string value)
        {
            logger.LogInformation("Removing claim {ClaimType} from user with subject: {Subject}", type, subject);

            var user = await UserManager.FindByIdAsync(subject);
            if (user == null)
            {
                logger.LogWarning("User not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Removing claim {ClaimType} with value '{ClaimValue}' from user {Username}", type, value, user.UserName);

            var result = await UserManager.RemoveClaimAsync(user, new Claim(type, value));
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to remove claim {ClaimType} from user {Username}: {Errors}",
                    type, user.UserName, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully removed claim {ClaimType} from user {Username}", type, user.UserName);
            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<CreateResult>> CreateRoleAsync(IEnumerable<PropertyValue> properties)
        {
            logger.LogInformation("Creating new role");
            ValidateSupportsRoles();

            var nameClaim = properties.Single(x => x.Type == IdentityManagerConstants.ClaimTypes.Name);
            var name = nameClaim.Value;

            logger.LogDebug("Creating role with name: {RoleName}", name);

            var exclude = new[] { IdentityManagerConstants.ClaimTypes.Name };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            if (otherProperties.Any())
            {
                logger.LogDebug("Creating role with {PropertyCount} additional properties", otherProperties.Length);
            }

            var metadata = await GetMetadataAsync();
            var createProps = metadata.RoleMetadata.GetCreateProperties();

            var role = new TRole { Name = name };
            foreach (var prop in otherProperties)
            {
                logger.LogDebug("Setting role property: {PropertyType} for role: {RoleName}", prop.Type, name);
                var roleResult = await SetRoleProperty(createProps, role, prop.Type, prop.Value);
                if (!roleResult.IsSuccess)
                {
                    logger.LogWarning("Failed to set role property {PropertyType} for role {RoleName}: {Errors}",
                        prop.Type, name, string.Join(", ", roleResult.Errors));
                    return new IdentityManagerResult<CreateResult>(roleResult.Errors.ToArray());
                }
            }

            var result = await RoleManager.CreateAsync(role);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to create role {RoleName}: {Errors}",
                    name, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully created role {RoleName} with ID: {RoleId}", name, role.Id);
            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = role.Id.ToString() });
        }

        public async Task<IdentityManagerResult> DeleteRoleAsync(string subject)
        {
            logger.LogInformation("Deleting role with subject: {Subject}", subject);
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null)
            {
                logger.LogWarning("Role not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Found role {RoleName} (ID: {RoleId}) for deletion", role.Name, role.Id);

            var result = await RoleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to delete role {RoleName} (ID: {RoleId}): {Errors}",
                    role.Name, role.Id, string.Join(", ", result.Errors.Select(x => x.Description)));
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            logger.LogInformation("Successfully deleted role {RoleName} (ID: {RoleId})", role.Name, role.Id);
            return IdentityManagerResult.Success;
        }

        public Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync(string filter, int start, int count)
        {
            logger.LogInformation("Querying roles with filter: '{Filter}', start: {Start}, count: {Count}", filter ?? "(none)", start, count);
            ValidateSupportsRoles();

            if (start < 0) start = 0;
            if (count < 0) count = int.MaxValue;

            var query =
                from role in RoleManager.Roles
                orderby role.Name
                select role;

            if (!string.IsNullOrWhiteSpace(filter))
            {
                query =
                    from role in query
                    where role.Name.Contains(filter)
                    orderby role.Name
                    select role;
            }

            var total = query.Count();
            var roles = query.Skip(start).Take(count).ToArray();

            logger.LogDebug("Query returned {ResultCount} roles out of {TotalCount} total", roles.Length, total);

            var result = new QueryResult<RoleSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter,
                Items = roles.Select(x =>
                {
                    var user = new RoleSummary
                    {
                        Subject = x.Id.ToString(),
                        Name = x.Name,
                        // TODO: Role Description
                    };

                    return user;
                }).ToArray()
            };

            logger.LogInformation("Successfully queried roles: returned {ResultCount} roles", result.Items.Count);
            return Task.FromResult(new IdentityManagerResult<QueryResult<RoleSummary>>(result));
        }

        public async Task<IdentityManagerResult<RoleDetail>> GetRoleAsync(string subject)
        {
            logger.LogInformation("Getting role details for subject: {Subject}", subject);
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null)
            {
                logger.LogWarning("Role not found with subject: {Subject}", subject);
                return new IdentityManagerResult<RoleDetail>((RoleDetail)null);
            }

            logger.LogDebug("Found role {RoleName} (ID: {RoleId})", role.Name, role.Id);

            var result = new RoleDetail
            {
                Subject = subject,
                Name = role.Name,
                // TODO: Role Description
            };

            var metadata = await GetMetadataAsync();

            var props = new List<PropertyValue>();
            foreach (var prop in metadata.RoleMetadata.UpdateProperties)
            {
                props.Add(new PropertyValue
                {
                    Type = prop.Type,
                    Value = await GetRoleProperty(prop, role)
                });
            }

            result.Properties = props.ToArray();
            logger.LogDebug("Retrieved {PropertyCount} properties for role {RoleName}", props.Count, role.Name);

            logger.LogInformation("Successfully retrieved details for role {RoleName}", role.Name);
            return new IdentityManagerResult<RoleDetail>(result);
        }

        public async Task<IdentityManagerResult> SetRolePropertyAsync(string subject, string type, string value)
        {
            logger.LogInformation("Setting role property {PropertyType} for subject: {Subject}", type, subject);
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null)
            {
                logger.LogWarning("Role not found with subject: {Subject}", subject);
                return new IdentityManagerResult("Invalid subject");
            }

            logger.LogDebug("Setting property {PropertyType} to value '{Value}' for role {RoleName}", type, value, role.Name);

            var errors = ValidateRoleProperty(type, value).ToList();
            if (errors.Any())
            {
                logger.LogWarning("Validation failed for role property {PropertyType}: {Errors}", type, string.Join(", ", errors));
                return new IdentityManagerResult(errors.ToArray());
            }

            var metadata = await GetMetadataAsync();
            var result = await SetRoleProperty(metadata.RoleMetadata.UpdateProperties, role, type, value);
            if (!result.IsSuccess)
            {
                logger.LogWarning("Failed to set role property {PropertyType} for role {RoleName}: {Errors}",
                    type, role.Name, string.Join(", ", result.Errors));
                return result;
            }

            var updateResult = await RoleManager.UpdateAsync(role);
            if (!updateResult.Succeeded)
            {
                logger.LogWarning("Failed to update role {RoleName} after setting property {PropertyType}: {Errors}",
                    role.Name, type, string.Join(", ", updateResult.Errors.Select(x => x.Description)));
                return new IdentityManagerResult(result.Errors.ToArray());
            }

            logger.LogInformation("Successfully set property {PropertyType} for role {RoleName}", type, role.Name);
            return IdentityManagerResult.Success;
        }

        public virtual Task<IdentityManagerMetadata> GetStandardMetadata(bool includeAccountProperties = true)
        {
            logger.LogDebug("Getting standard metadata with includeAccountProperties: {IncludeAccountProperties}", includeAccountProperties);

            var update = new List<PropertyMetadata>();
            if (UserManager.SupportsUserPassword)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(IdentityManagerConstants.ClaimTypes.Password, u => Task.FromResult<string>(null), SetPassword, "Password", PropertyDataType.Password, true));
                logger.LogDebug("Added password metadata");
            }
            if (UserManager.SupportsUserEmail)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(IdentityManagerConstants.ClaimTypes.Email, u => GetEmail(u), SetEmail, "Email", PropertyDataType.Email));
                logger.LogDebug("Added email metadata");
            }
            if (UserManager.SupportsUserPhoneNumber)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(IdentityManagerConstants.ClaimTypes.Phone, u => GetPhone(u), SetPhone, "Phone", PropertyDataType.String));
                logger.LogDebug("Added phone metadata");
            }
            if (UserManager.SupportsUserTwoFactor)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("two_factor", u => GetTwoFactorEnabled(u), SetTwoFactorEnabled, "Two Factor Enabled", PropertyDataType.Boolean));
                logger.LogDebug("Added two-factor metadata");
            }
            if (UserManager.SupportsUserLockout)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked_enabled", GetLockoutEnabled, (user1, enabled) => SetLockoutEnabled(user1, enabled), "Lockout Enabled", PropertyDataType.Boolean));
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked", GetLockedOut, (user1, locked) => SetLockedOut(user1, locked), "Locked Out", PropertyDataType.Boolean));
                logger.LogDebug("Added lockout metadata");
            }

            if (includeAccountProperties)
            {
                update.AddRange(PropertyMetadata.FromType<TUser>());
                logger.LogDebug("Added account properties from TUser type");
            }

            var create = new List<PropertyMetadata>();
            create.Add(PropertyMetadata.FromProperty<TUser>(x => x.UserName, name: IdentityManagerConstants.ClaimTypes.Username, required: true));
            create.Add(PropertyMetadata.FromFunctions<TUser, string>(IdentityManagerConstants.ClaimTypes.Password, u => Task.FromResult<string>(null), SetPassword, "Password", PropertyDataType.Password, true));

            var user = new UserMetadata
            {
                SupportsCreate = true,
                SupportsDelete = true,
                SupportsClaims = UserManager.SupportsUserClaim,
                CreateProperties = create,
                UpdateProperties = update
            };

            var role = new RoleMetadata
            {
                RoleClaimType = RoleClaimType,
                SupportsCreate = true,
                SupportsDelete = true,
                CreateProperties = [
                    PropertyMetadata.FromProperty<TRole>(x=>x.Name, name: IdentityManagerConstants.ClaimTypes.Name, required: true),
                ]
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = user,
                RoleMetadata = role
            };

            logger.LogInformation("Standard metadata created with {CreatePropertyCount} create properties and {UpdatePropertyCount} update properties",
                create.Count, update.Count);

            return Task.FromResult(meta);
        }

        public virtual PropertyMetadata GetMetadataForClaim(string type, string name = null, PropertyDataType dataType = PropertyDataType.String, bool required = false)
        {
            logger.LogDebug("Getting metadata for claim type: {ClaimType}", type);
            return PropertyMetadata.FromFunctions(type, GetForClaim(type), SetForClaim(type), name, dataType, required);
        }

        public virtual Func<TUser, Task<string>> GetForClaim(string type)
        {
            return async user => (await UserManager.GetClaimsAsync(user)).Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();
        }

        public virtual Func<TUser, string, Task<IdentityManagerResult>> SetForClaim(string type)
        {
            return async (user, value) =>
            {
                logger.LogDebug("Setting claim {ClaimType} for user {Username}", type, user.UserName);

                var claims = await UserManager.GetClaimsAsync(user);
                claims = claims.Where(x => x.Type == type).ToArray();

                foreach (var claim in claims)
                {
                    var result = await UserManager.RemoveClaimAsync(user, claim);
                    if (!result.Succeeded)
                    {
                        logger.LogWarning("Failed to remove existing claim {ClaimType} for user {Username}: {Error}",
                            type, user.UserName, result.Errors.First().Description);
                        return new IdentityManagerResult(result.Errors.First().Description);
                    }
                }

                if (!string.IsNullOrWhiteSpace(value))
                {
                    var result = await UserManager.AddClaimAsync(user, new Claim(type, value));
                    if (!result.Succeeded)
                    {
                        logger.LogWarning("Failed to add claim {ClaimType} for user {Username}: {Error}",
                            type, user.UserName, result.Errors.First().Description);
                        return new IdentityManagerResult(result.Errors.First().Description);
                    }
                    logger.LogDebug("Successfully set claim {ClaimType} for user {Username}", type, user.UserName);
                }
                else
                {
                    logger.LogDebug("Cleared claim {ClaimType} for user {Username}", type, user.UserName);
                }

                return IdentityManagerResult.Success;
            };
        }

        public virtual async Task<IdentityManagerResult> SetPassword(TUser user, string password)
        {
            logger.LogInformation("Setting password for user {Username}", user.UserName);

            var token = await UserManager.GeneratePasswordResetTokenAsync(user);
            var result = await UserManager.ResetPasswordAsync(user, token, password);

            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set password for user {Username}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            logger.LogInformation("Successfully set password for user {Username}", user.UserName);
            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult> SetUsername(TUser user, string username)
        {
            logger.LogInformation("Setting username for user {OldUsername} to {NewUsername}", user.UserName, username);

            var result = await UserManager.SetUserNameAsync(user, username);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set username for user {OldUsername}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            logger.LogInformation("Successfully set username to {NewUsername}", username);
            return IdentityManagerResult.Success;
        }

        public virtual Task<string> GetEmail(TUser user) => UserManager.GetEmailAsync(user);

        public virtual async Task<IdentityManagerResult> SetEmail(TUser user, string email)
        {
            logger.LogInformation("Setting email for user {Username} to {Email}", user.UserName, email);

            var result = await UserManager.SetEmailAsync(user, email);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set email for user {Username}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            if (!string.IsNullOrWhiteSpace(email))
            {
                logger.LogDebug("Confirming email for user {Username}", user.UserName);
                var token = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                result = await UserManager.ConfirmEmailAsync(user, token);  // TODO: check internal usage of reset/confirmation tokens is still valid
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed to confirm email for user {Username}: {Error}",
                        user.UserName, result.Errors.First().Description);
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
                logger.LogDebug("Email confirmed for user {Username}", user.UserName);
            }

            logger.LogInformation("Successfully set email for user {Username}", user.UserName);
            return IdentityManagerResult.Success;
        }

        public virtual Task<string> GetPhone(TUser user) => UserManager.GetPhoneNumberAsync(user);

        public virtual async Task<IdentityManagerResult> SetPhone(TUser user, string phone)
        {
            logger.LogInformation("Setting phone number for user {Username} to {Phone}", user.UserName, phone);

            var result = await UserManager.SetPhoneNumberAsync(user, phone);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set phone number for user {Username}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            if (!string.IsNullOrWhiteSpace(phone))
            {
                logger.LogDebug("Confirming phone number for user {Username}", user.UserName);
                var token = await UserManager.GenerateChangePhoneNumberTokenAsync(user, phone);
                result = await UserManager.ChangePhoneNumberAsync(user, phone, token);
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed to confirm phone number for user {Username}: {Error}",
                        user.UserName, result.Errors.First().Description);
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
                logger.LogDebug("Phone number confirmed for user {Username}", user.UserName);
            }

            logger.LogInformation("Successfully set phone number for user {Username}", user.UserName);
            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetTwoFactorEnabled(TUser user) => UserManager.GetTwoFactorEnabledAsync(user);

        public virtual async Task<IdentityManagerResult> SetTwoFactorEnabled(TUser user, bool enabled)
        {
            logger.LogInformation("Setting two-factor authentication for user {Username} to {Enabled}", user.UserName, enabled);

            var result = await UserManager.SetTwoFactorEnabledAsync(user, enabled);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set two-factor authentication for user {Username}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            logger.LogInformation("Successfully set two-factor authentication for user {Username} to {Enabled}", user.UserName, enabled);
            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetLockoutEnabled(TUser user) => UserManager.GetLockoutEnabledAsync(user);

        public virtual async Task<IdentityManagerResult> SetLockoutEnabled(TUser user, bool enabled)
        {
            logger.LogInformation("Setting lockout enabled for user {Username} to {Enabled}", user.UserName, enabled);

            var result = await UserManager.SetLockoutEnabledAsync(user, enabled);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set lockout enabled for user {Username}: {Error}",
                    user.UserName, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            logger.LogInformation("Successfully set lockout enabled for user {Username} to {Enabled}", user.UserName, enabled);
            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetLockedOut(TUser user) => UserManager.IsLockedOutAsync(user);

        public virtual async Task<IdentityManagerResult> SetLockedOut(TUser user, bool locked)
        {
            logger.LogInformation("Setting locked out status for user {Username} to {Locked}", user.UserName, locked);

            if (locked)
            {
                var result = await UserManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed to lock out user {Username}: {Error}",
                        user.UserName, result.Errors.First().Description);
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
                logger.LogInformation("Successfully locked out user {Username}", user.UserName);
            }
            else
            {
                var result = await UserManager.SetLockoutEndDateAsync(user, DateTimeOffset.MinValue);
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed to unlock user {Username}: {Error}",
                        user.UserName, result.Errors.First().Description);
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
                logger.LogInformation("Successfully unlocked user {Username}", user.UserName);
            }

            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult> SetName(TRole role, string name)
        {
            logger.LogInformation("Setting role name from {OldName} to {NewName}", role.Name, name);

            var result = await RoleManager.SetRoleNameAsync(role, name);
            if (!result.Succeeded)
            {
                logger.LogWarning("Failed to set role name from {OldName} to {NewName}: {Error}",
                    role.Name, name, result.Errors.First().Description);
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            logger.LogInformation("Successfully set role name to {NewName}", name);
            return IdentityManagerResult.Success;
        }

        protected virtual Task<string> GetUserProperty(PropertyMetadata propMetadata, TUser user)
        {
            if (propMetadata.TryGet(user, out var val)) return val;

            logger.LogError("Invalid user property type: {PropertyType} for user {Username}", propMetadata.Type, user.UserName);
            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual Task<IdentityManagerResult> SetUserProperty(IEnumerable<PropertyMetadata> propsMeta, TUser user, string type, string value)
        {
            if (propsMeta.TrySet(user, type, value, out var result)) return result;

            logger.LogError("Invalid user property type: {PropertyType} for user {Username}", type, user.UserName);
            throw new Exception("Invalid property type " + type);
        }

        protected virtual async Task<string> DisplayNameFromUser(TUser user)
        {
            if (UserManager.SupportsUserClaim)
            {
                var claims = await UserManager.GetClaimsAsync(user);
                var name = claims.Where(x => x.Type == IdentityManagerConstants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(name))
                {
                    logger.LogDebug("Display name for user {Username}: {DisplayName}", user.UserName, name);
                    return name;
                }
            }

            logger.LogDebug("No display name found for user {Username}", user.UserName);
            return null;
        }

        protected virtual IEnumerable<string> ValidateUserProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual void ValidateSupportsRoles()
        {
            if (RoleManager == null)
            {
                logger.LogError("Roles are not supported - RoleManager is null");
                throw new InvalidOperationException("Roles Not Supported");
            }
        }

        protected virtual Task<string> GetRoleProperty(PropertyMetadata propMetadata, TRole role)
        {
            if (propMetadata.TryGet(role, out var val)) return val;

            logger.LogError("Invalid role property type: {PropertyType} for role {RoleName}", propMetadata.Type, role.Name);
            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual IEnumerable<string> ValidateRoleProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual Task<IdentityManagerResult> SetRoleProperty(IEnumerable<PropertyMetadata> propsMeta, TRole role, string type, string value)
        {
            if (propsMeta.TrySet(role, type, value, out var result)) return result;

            logger.LogError("Invalid role property type: {PropertyType} for role {RoleName}", type, role.Name);
            throw new Exception("Invalid property type " + type);
        }
    }
}
