import echo_core as core


class EchoGateway:

    def __init__(self):
        self.resources = {
            "demo-folder": {
                "message": "This is a protected demo resource."
            },
            "public-data": {
                "message": "This is public demo data."
            }
        }

    def execute(self, agent_token, action, resource):

        agent = core.get_agent_by_token(agent_token)

        if not agent:
            return {
                "success": False,
                "error": "Invalid agent credentials"
            }

        decision = core.authorize(
            agent,
            action,
            resource
        )

        if not decision["allowed"]:

            return {
                "success": False,
                "blocked": True,
                "reason": decision["reason"]
            }

        if action == "resource.read":

            if resource not in self.resources:

                return {
                    "success": False,
                    "error": "Resource does not exist"
                }

            return {
                "success": True,
                "data": self.resources[resource]
            }

        return {
            "success": False,
            "error": "Unsupported action"
        }
