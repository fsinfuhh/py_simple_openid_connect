import { Provider } from "oidc-provider"
import yaml from "js-yaml"
import fs from "fs"
import path from "path"
import { fileURLToPath } from "url"

const baseDir = path.dirname(fileURLToPath(import.meta.url))
const yamlConfig = yaml.load(fs.readFileSync(path.join(baseDir, "config.yml")))

const configuration = {
    clients: [{
        client_id: yamlConfig.client_id,
        client_secret: yamlConfig.client_secret,
        redirect_uris: yamlConfig.redirect_uris,
    }],
    claims: {
        email: ["email"],
        profile: ["preferred_username"],
    },
    pkce: {
        required: () => false,
    },
    findAccount: async (ctx, id) => {
        return {
            accountId: id,
            async claims(use, scope) { return {
                sub: id,
                email: "test@example.com",
                preferred_username: "test",
            } }
        }
    }
}

const oidc = new Provider(`http://localhost:${yamlConfig.port}`, configuration)
oidc.callback()
oidc.listen(yamlConfig.port, () => {
    console.log(`dummy provider listening on port ${yamlConfig.port}, check http://localhost:${yamlConfig.port}/.well-known/openid-configuration for its configuration`)
})
