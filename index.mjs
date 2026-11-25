import {
  check,
  connection,
  count,
  error,
  environment,
  fromPath,
  includesAll,
  matchesState,
  positiveID,
  query,
  safeEndpoint,
  secretPath,
  segment,
  setting,
  service,
  stateOption,
  text,
  verdict,
  workURL,
  z,
} from '@cairul/plugin-kit';
import { installationCredential } from './app-auth.mjs';

const locator = { repository: text.regex(/^[^/]+\/[^/]+$/).optional(), number: positiveID.optional() };
const sha = z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i);

export default function github({ graphqlUrl, appId, installationId, privateKeyFile, authMode, ...options } = {}) {
  const prefix = 'GITHUB';
  const base = safeEndpoint(setting(prefix, 'BASE_URL', options.baseUrl ?? 'https://api.github.com'));
  const graphBase = safeEndpoint(
    setting(prefix, 'GRAPHQL_URL', graphqlUrl ?? base.href.replace(/\/api\/v3\/?$/, '/api'))
  );
  if (base.origin !== graphBase.origin) throw new Error('GitHub REST and GraphQL must use the same service origin.');
  const app = {
    appId: setting(prefix, 'APP_ID', environment('GITHUB_APP_ID') ?? appId),
    installationId: setting(prefix, 'INSTALLATION_ID', environment('GITHUB_INSTALLATION_ID') ?? installationId),
    privateKeyFile,
  };
  const envApp = ['APP_ID', 'INSTALLATION_ID', 'APP_PRIVATE_KEY', 'APP_PRIVATE_KEY_FILE', 'APP_PRIVATE_KEY_ENV'].some(
    (name) => setting(prefix, name)
  );
  const envToken = ['TOKEN', 'TOKEN_FILE', 'TOKEN_ENV'].some((name) => setting(prefix, name));
  const hasApp = app.appId || app.installationId || privateKeyFile || environment('GITHUB_APP_PRIVATE_KEY');
  const defaultMode = envApp ? 'app' : envToken ? 'token' : (authMode ?? (hasApp ? 'app' : 'token'));
  const mode = z.enum(['app', 'token']).safeParse(setting(prefix, 'AUTH_MODE', defaultMode));
  if (!mode.success) throw new Error('GitHub authMode must be app or token.');
  if (privateKeyFile !== undefined) secretPath.parse(privateKeyFile);
  const getToken = mode.data === 'app' ? installationCredential(base, app) : undefined;
  const defaults = { prefix, tokenEnv: 'GITHUB_TOKEN', credential: getToken };
  const api = connection(options, {
    ...defaults,
    endpoint: base.href,
    headers: { 'x-github-api-version': '2022-11-28' },
  });
  const graph = connection(options, {
    ...defaults,
    endpoint: graphBase.href,
    required: true,
  });
  const hosts = api.host === 'api.github.com' ? ['github.com'] : [api.host];
  function location({ repository, number }, context, type) {
    if (!repository || !number) {
      const path =
        type === 'pulls' ? /^\/([^/]+)\/([^/]+)\/pull\/(\d+)(?:\/|$)/ : /^\/([^/]+)\/([^/]+)\/issues\/(\d+)(?:\/|$)/;
      const [owner, repo, id] = fromPath(workURL(context.workItemUrl, hosts), path);
      repository ??= `${owner}/${repo}`;
      number ??= id;
    }
    return [`repos/${repository.split('/').map(segment).join('/')}`, number, repository];
  }

  function resource(type, inputs, evaluate) {
    return check(z.strictObject({ ...locator, ...inputs }), (config, context) =>
      service(async () => {
        const [repo, number] = location(config, context, type);
        const path = `${repo}/${type}/${number}`;
        const read = (suffix = '', query) => api.request(`${path}${suffix}`, { signal: context.signal, query });
        return evaluate(config, read);
      })
    );
  }

  return {
    checkKinds: {
      'github.issue-state': resource('issues', { state: stateOption }, async ({ state }, read) =>
        matchesState((await read()).state, state, 'Issue')
      ),
      'github.issue-labels': resource('issues', { labels: z.array(text).min(1) }, async ({ labels }, read) =>
        includesAll(
          (await read()).labels?.map((label) => label.name),
          labels,
          'issue labels'
        )
      ),
      'github.issue-linked-prs-merged': check(z.strictObject(locator), (config, context) =>
        service(async () => {
          const [, number, repository] = location(config, context, 'issues');
          const [owner, name] = repository.split('/');
          const document = `query CairulLinkedPullRequests($owner: String!, $name: String!, $number: Int!, $after: String) {
          repository(owner: $owner, name: $name) {
            issue(number: $number) {
              closedByPullRequestsReferences(first: 100, after: $after, includeClosedPrs: true) {
                totalCount nodes { state } pageInfo { hasNextPage endCursor }
              }
            }
          }
        }`;
          let after = null;
          let read = 0;
          let outstanding = 0;
          for (let page = 1; page <= 20; page++) {
            const { data, errors } = await query(
              graph,
              'graphql',
              {
                query: document,
                variables: { owner, name, number: Number(number), after },
              },
              context.signal
            );
            const links = data?.repository?.issue?.closedByPullRequestsReferences;
            if (errors?.length || !Array.isArray(links?.nodes) || typeof links.pageInfo?.hasNextPage !== 'boolean') {
              return error('GitHub did not return linked pull requests.');
            }
            read += links.nodes.length;
            outstanding += links.nodes.filter((pr) => pr?.state !== 'MERGED').length;
            if (!links.pageInfo.hasNextPage) {
              if (links.totalCount !== read) return error('GitHub returned an incomplete linked pull request list.');
              return verdict(
                read > 0 && outstanding === 0,
                read
                  ? `${outstanding} of ${read} linked pull requests need merging.`
                  : 'No closing pull requests linked.'
              );
            }
            if (!links.pageInfo.endCursor || links.pageInfo.endCursor === after)
              return error('GitHub returned an invalid pagination cursor.');
            after = links.pageInfo.endCursor;
          }
          return error('GitHub returned too many linked pull request pages.');
        })
      ),
      'github.pr-merged': resource('pulls', {}, async (_, read) => {
        const { merged } = await read();
        if (typeof merged !== 'boolean') return error('GitHub returned no merge status.');
        return verdict(merged, merged ? 'Pull request merged.' : 'Waiting for pull request merge.');
      }),
      'github.pr-approvals': resource('pulls', { minimum: count.min(1).default(1) }, async ({ minimum }, read) => {
        const reviewers = new Map();
        for (let page = 1; page <= 20; page++) {
          const reviews = await read('/reviews', { per_page: 100, page });
          if (!Array.isArray(reviews)) return error('GitHub returned no review list.');
          for (const review of reviews) {
            if (review.user?.login && ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(review.state)) {
              reviewers.set(review.user.login, review.state);
            }
          }
          if (reviews.length < 100) {
            const approved = [...reviewers.values()].filter((state) => state === 'APPROVED').length;
            return verdict(approved >= minimum, `${approved} of ${minimum} required approvals.`);
          }
        }
        return error('GitHub returned too many review pages to evaluate.');
      }),
      'github.deployment-succeeded': check(
        z.strictObject({ repository: locator.repository.unwrap(), sha, environment: text }),
        (config, { signal }) =>
          service(async () => {
            const repo = `repos/${config.repository.split('/').map(segment).join('/')}`;
            const deployments = await api.request(`${repo}/deployments`, {
              signal,
              query: { sha: config.sha, environment: config.environment, per_page: 1 },
            });
            if (!Array.isArray(deployments)) return error('GitHub returned no deployment list.');
            if (!deployments.length) return verdict(false, 'Waiting for deployment.');
            const statuses = await api.request(`${repo}/deployments/${positiveID.parse(deployments[0].id)}/statuses`, {
              signal,
              query: { per_page: 1 },
            });
            if (!Array.isArray(statuses)) return error('GitHub returned no deployment statuses.');
            return statuses.length
              ? matchesState(statuses[0].state, 'success', 'Deployment')
              : verdict(false, 'Waiting for deployment status.');
          })
      ),
      'github.check-passed': check(
        z.strictObject({ ...locator, sha: sha.optional(), name: text, app: text.optional() }),
        (config, context) =>
          service(async () => {
            const { name, app, sha: explicitSHA } = config;
            const [repo, number] =
              explicitSHA && config.repository
                ? [`repos/${config.repository.split('/').map(segment).join('/')}`]
                : location(config, context, 'pulls');
            const revision =
              explicitSHA ??
              sha.parse((await api.request(`${repo}/pulls/${number}`, { signal: context.signal })).head?.sha);
            const { check_runs: runs, total_count: total } = await api.request(
              `${repo}/commits/${revision}/check-runs`,
              {
                signal: context.signal,
                query: { check_name: name, filter: 'latest', per_page: 100 },
              }
            );
            if (!Array.isArray(runs) || total > runs.length)
              return error('GitHub returned an incomplete check-run list.');
            const selected = runs.filter((run) => run.name === name && (!app || run.app?.slug === app));
            return verdict(
              selected.length > 0 &&
                selected.every((run) => run.status === 'completed' && run.conclusion === 'success'),
              `Waiting for "${name}" to succeed on commit ${revision.slice(0, 12)}.`
            );
          })
      ),
    },
  };
}
