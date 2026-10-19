/**
 * Módulo: Motor Heurístico Anti-Automação & Silent Shadowbanning
 * Descrição: Detecta scripts automatizados analisando a cadência e a variância temporal
 * entre requisições sucessivas, aplicando contenção silenciosa (Shadowban).
 */

const MIN_INTERVAL_MS = 15000;          // Cooldown mínimo esperado entre operações
const ROBOTIC_JITTER_TOLERANCE = 1000;  // Janela de precisão suspeita (1s)
const MAX_SUSPICION_THRESHOLD = 20;     // Limiar para ativação automática de Shadowban
const TELEMETRY_WINDOW_SIZE = 15;       // Tamanho da fila circular de timestamps

/**
 * Avalia o histórico temporal do usuário e atualiza o score de anomalia.
 */
function evaluateRequestCadence(userDocument) {
    const now = new Date();

    if (!userDocument.securityData) {
        userDocument.securityData = { lastClaims: [], suspicionScore: 0 };
    }

    const history = userDocument.securityData.lastClaims;

    if (history.length > 0) {
        const lastTimestamp = new Date(history[history.length - 1]);
        const deltaMs = now.getTime() - lastTimestamp.getTime();

        // Se a requisição ocorre repetidamente logo após o término do cooldown (baixa entropia humana)
        if (deltaMs >= MIN_INTERVAL_MS && deltaMs <= (MIN_INTERVAL_MS + ROBOTIC_JITTER_TOLERANCE)) {
            userDocument.securityData.suspicionScore += 1;
        } else if (deltaMs > (MIN_INTERVAL_MS + 10000)) {
            // Decaimento gradual do score em caso de comportamento orgânico espaçado
            userDocument.securityData.suspicionScore = Math.max(0, userDocument.securityData.suspicionScore - 1);
        }
    }

    history.push(now);
    if (history.length > TELEMETRY_WINDOW_SIZE) {
        history.shift();
    }

    if (userDocument.securityData.suspicionScore >= MAX_SUSPICION_THRESHOLD) {
        userDocument.isFlaggedAutomation = true;
    }

    return userDocument;
}

/**
 * Exemplo de Handler com Silent Shadowbanning
 * Retorna payload idêntico ao de sucesso com recompensa zerada para enganar o script atacante.
 */
async function protectedTransactionHandler(req, res, UserModel) {
    let user = await UserModel.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'Account not found' });

    if (user.isFlaggedAutomation === true) {
        return res.status(200).json({
            success: true,
            creditedAmount: 0,
            status: 'processed_simulated'
        });
    }

    user = evaluateRequestCadence(user);
    await user.save();

    return res.status(200).json({
        success: true,
        creditedAmount: req.body.requestedAmount,
        status: 'processed'
    });
}

module.exports = { evaluateRequestCadence, protectedTransactionHandler };
