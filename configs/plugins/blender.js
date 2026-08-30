// ZLOYMOLODOY SPECIAL FOR PSTN 2025

import BasePlugin from './base-plugin.js';

export default class blender extends BasePlugin {
    static get description() {
        return (
            "Команда нужна для шафла команд"
        );
    }

    static get defaultEnabled() {
        return true;
    }

    static get optionsSpecification() {
        return {
            command: {
                required: false,
                description: 'Команда нужна для шафла команд',
                default: 'command'
            }
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

    async onChatCommand(info) {
        try {
            if (info.chat !== 'ChatAdmin') return;

            const players = this.server.players.slice(0);
            if (players.length < 2) return;

            // Перемешиваем игроков
            let currentIndex = players.length;
            let temporaryValue;
            let randomIndex;

            while (currentIndex !== 0) {
                randomIndex = Math.floor(Math.random() * currentIndex);
                currentIndex -= 1;

                temporaryValue = players[currentIndex];
                players[currentIndex] = players[randomIndex];
                players[randomIndex] = temporaryValue;
            }

            // Распределяем игроков по командам
            for (let i = 0; i < players.length; i++) {
                const player = players[i];
                const targetTeam = i % 2 === 0 ? '1' : '2';
                
                // Переключаем только если игрок не в нужной команде
                if (player.teamID !== targetTeam) {
                    await this.server.rcon.switchTeam(player.eosID);
                }
            }
            
            await this.server.rcon.warn("Команды успешно перемешаны");
        } catch (e) {
            await this.sendError(e);
        }
    }

    // Вспомогательный метод для перемешивания массива
    shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
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
                    title: `Ошибка в blender.js: \n\n${error.name} ${error.message}\n ${error.stack}`,
                    color: 5814783,
                }],
                attachments: []
            })
        })
    }
}
