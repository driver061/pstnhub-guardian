// SVAR / ZLOYMOLODOY FOR PSTN 2024
import BasePlugin from './base-plugin.js';

export default class roll extends BasePlugin {

    static get description() {
        return (
            'roll'
        );
    }

    static get defaultEnabled() {
        return true;
    }

    static get optionsSpecification() {
        return {
            command: {
                required: false,
                description: 'Roll',
                default: 'command',
            },
        };
    }

    constructor(server, options, connectors) {
        super(server, options, connectors);

        this.onChatCommand = this.onChatCommand.bind(this);
    }

    async mount() {
        this.server.on(`CHAT_COMMAND:${this.options.command}`, this.onChatCommand);
    }

    async unmount() {
        this.server.removeEventListener(`CHAT_COMMAND:${this.options.command}`, this.onChatCommand);
    }


    Users = []
    timer = null

    async onChatCommand(info) {

        try {
            let playerName = info.player.name;
            let id = info.player.steamID
            // let teamID = parseInt(info.player.squad.teamID) - 1

            if (!this.checkUser(id)) {
                let result = this.randomFunction(1, 100)
                if (this.timer === null) {
                    this.timer = setTimeout(() => this.resultGame(), 20000)
                    await this.server.rcon.warn(id, `Ваш результат: ${result}\nОбщие результаты будут через 20 секунд`);
                }

                this.Users.push({name: playerName, id: id, result: result});
                await this.server.rcon.warn(id, `Ваш результат: ${result}\nЖдем окончания игры`)
            }

        } catch (e) {
            await this.sendError(e)
        }
    }

    checkUser(id) {
        let isUser = false
        this.Users.forEach(user => {
            if (user.id === id) isUser = true
        })

        return isUser;
    }

    randomFunction(min, max) {
        return Math.round(min + Math.random() * (max - min));
    }

    clearUsersParam() {
        this.Users = []
        this.timer = null
    }

    async resultGame() {
        try {
            let message = 'Результаты игры:\n'

            this.Users.forEach((user, userId) => {
                message = message + `${user.name} - ${user.result}` + `${userId === this.Users.length ? '' : '\n'}`;
            })

            for (const user of this.Users) {
                await this.server.rcon.warn(user.id, message)
            }

            await this.sendResult(message)

            this.clearUsersParam()
        } catch (e) {
            await this.sendError(e)
        }
    }


    async sendResult(message) {
        await fetch('https://discord.com/api/webhooks/1222158312015921235/9aWOQdloTnN4b-ImassOxpnt_YmLRY27ZSPYm0_mjbEASzGODJuSxS_RQWSX8YD4kdMV', {
            method: "POST",
            headers: {
                "Content-Type": 'application/json'
            },
            body: JSON.stringify({
                content: "",
                embeds: [
                    {
                        title: `Игра`,
                        color: 5814783,
                        description: message.replace('Результаты игры:\n', '')
                    }
                ],
                attachments: []
            })
        })
    }

    async sendError(error) {
        await fetch('https://discord.com/api/webhooks/1252583171426619443/-d3FC8_L0KFXdPBsQfW37wurD5Cz9KUlukvgPQdvXqspXL7J8b-nbkPOVvYLsErjyfU0', {
            method: "POST",
            headers: {
                "Content-Type": 'application/json'
            },
            body: JSON.stringify({
                content: '',
                embeds: [{
                    title: `Ошибка в roll.js: \n\n${error.name} ${error.message}\n ${error.stack}`,
                    color: 5814783,
                }],
                attachments: []
            })
        })
    }
}