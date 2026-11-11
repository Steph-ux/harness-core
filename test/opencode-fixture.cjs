/**
 * The shared fixture for the OpenCode surface tests.
 *
 * It builds a context shaped like the one OpenCode hands to a plugin, so the
 * proof and the context can be exercised without a model and without a host.
 */
const path = require("node:path");

/**
 * The teardowns a suite opened.
 *
 * The plugin holds open handles on the SQLite files of the state directory.
 * The host unloads a plugin and the store is closed with it; a suite that
 * removes its workspace has to unload the plugin first, exactly as the host
 * does, or the directory cannot be removed.
 *
 * The registry is emptied by every unload, so a suite only ever releases
 * the plugins it opened.
 */
const teardowns = new Set();

/** Unload every plugin a suite opened. */
async function unloadPlugins() {
  const opened = [...teardowns];
  teardowns.clear();
  for (const teardown of opened) {
    try {
      await teardown();
    } catch {
      /* the plugin was already unloaded */
    }
  }
}

/**
 * @param {string} directory the instance directory
 * @param {string} sessionDirectory the directory the sessions live in
 */
function makeContext(directory, sessionDirectory) {
  const hooks = new Map();
  const tools = new Map();
  const sessions = new Map();
  const ctx = {
    location: {
      directory,
      project: { id: "test", directory, canonical: directory },
    },
    app: { version: "test" },
    permission: { assert: async () => {}, explicit: async () => "once" },
    session: {
      get: async ({ sessionID } = {}) => ({
        id: sessionID,
        location: {
          directory: sessions.get(sessionID) ?? sessionDirectory ?? directory,
        },
      }),
      hook: async (name, callback) => {
        hooks.set(name, callback);
        return { dispose: async () => {} };
      },
    },
    tool: {
      hook: async (name, callback) => {
        hooks.set(name, callback);
        return { dispose: async () => {} };
      },
      transform: async (callback) => {
        callback({
          add: (definition) => tools.set(definition.name, definition),
          list: () => [...tools.values()],
          get: (id) => tools.get(id),
          remove: () => {},
          update: () => {},
          namespace: () => {},
        });
        return { dispose: async () => {} };
      },
      list: async () => [...tools.values()],
    },
    /**
     * The independent verifier. It has no tools and no session, so it can
     * only answer from what the prompt carries.
     */
    generate: {
      text: async ({ model, prompt } = {}) => {
        generated.push({ model, prompt });
        if (failing.has(`${model?.providerID}/${model?.id}`))
          throw new Error("provider refused the direct call");
        return { text: answer.value };
      },
    },
    /** The models the host offers. */
    model: {
      list: async () => models,
    },
    /** The skills the host offers. */
    skill: {
      transform: async (callback) => {
        skillTransforms.push(callback);
        callback({
          add: (definition) => skillRegistry.set(definition.id, definition),
          update: (id, change) => {
            const current = skillRegistry.get(id);
            if (current) skillRegistry.set(id, { ...current, ...change });
          },
          remove: (id) => skillRegistry.delete(id),
          get: (id) => skillRegistry.get(id),
          list: () => [...skillRegistry.values()],
        });
        return { dispose: async () => {} };
      },
      list: async () => [...skillRegistry.values()],
      reload: async () => {
        skillRegistry.clear();
        for (const callback of skillTransforms) callback(skillEditor());
      },
    },
  };
  const generated = [];
  const skillRegistry = new Map();
  const skillTransforms = [];
  const skillEditor = () => ({
    add: (definition) => skillRegistry.set(definition.id, definition),
    update: (id, change) => {
      const current = skillRegistry.get(id);
      if (current) skillRegistry.set(id, { ...current, ...change });
    },
    remove: (id) => skillRegistry.delete(id),
    get: (id) => skillRegistry.get(id),
    list: () => [...skillRegistry.values()],
  });
  const models = [
    { providerID: "opencode", id: "beam-free" },
    { providerID: "Ed", id: "glm-5.3-flash" },
  ];
  // The providers that refuse a direct call, as a region or a plan can.
  const failing = new Set();
  const answer = {
    value: '{"verdict":"confirmed","reason":"ok","evidence":[]}',
  };
  return {
    ctx,
    hooks,
    tools,
    sessions,
    generated,
    models,
    /** The providers that refuse a direct call, as a region or plan can. */
    failing,
    /** The skills the host currently serves. */
    skills: skillRegistry,
    /** The answer the verifier will give. */
    answer,
    /** The models the host offers. */
    set models(value) {
      models.length = 0;
      models.push(...value);
    },
    get models() {
      return models;
    },
    /** A context event as the host delivers it. */
    contextEvent(overrides = {}) {
      return {
        sessionID: "ses_test_0001",
        agent: "build",
        model: { providerID: "test", id: "test" },
        system: [
          { type: "text", text: "base prompt" },
          { type: "text", text: "another block" },
        ],
        messages: [],
        options: {},
        tools: {},
        ...overrides,
      };
    },
    coreDir: path.resolve(__dirname, ".."),
  };
}

/**
 * Load the plugin and remember its teardown, so unloadPlugins() releases
 * the handles it holds on the state directory.
 */
async function loadPlugin(plugin, ctx) {
  const teardown = await plugin.setup(ctx);
  if (typeof teardown === "function") teardowns.add(teardown);
  return teardown;
}

module.exports = { makeContext, loadPlugin, unloadPlugins };
