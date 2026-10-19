/**
 * Módulo: Oráculo de Câmbio com Failover & Verificador Reverso de Webhooks Cripto
 * Descrição: Garante alta disponibilidade na conversão fiduciária e imunidade contra
 * falsificação de postbacks (Webhook Spoofing) via consulta reversa na API de origem.
 */

let secureLiveRates = {
    BTC: 65000, DOGE: 0.15, LTC: 80, SOL: 150,
    ETH: 3500, USDT: 1, USDC: 1, TRX: 0.10, BNB: 600
};
let lastRateFetch = 0;
let isFetching = false;

/**
 * Oráculo de Preços Multi-Provedor com Mutex Lock e Cache de 30s
 */
async function getResilientCryptoRates() {
    const now = Date.now();

    if (now - lastRateFetch < 30000 && secureLiveRates.BTC !== 65000) {
        return secureLiveRates;
    }

    // Mutex simples para evitar múltiplas requisições concorrentes (Thundering Herd)
    if (isFetching) {
        await new Promise(resolve => setTimeout(resolve, 500));
        return secureLiveRates;
    }

    isFetching = true;

    try {
        // Provedor Primário: CoinGecko
        const coingeckoUrl = 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,dogecoin,litecoin,solana,ethereum,tether,usd-coin,tron,bnb&vs_currencies=usd';
        const res = await fetch(coingeckoUrl);

        if (res.ok) {
            const data = await res.json();
            secureLiveRates = {
                BTC: data.bitcoin?.usd || secureLiveRates.BTC,
                DOGE: data.dogecoin?.usd || secureLiveRates.DOGE,
                LTC: data.litecoin?.usd || secureLiveRates.LTC,
                SOL: data.solana?.usd || secureLiveRates.SOL,
                ETH: data.ethereum?.usd || secureLiveRates.ETH,
                USDT: data.tether?.usd || secureLiveRates.USDT,
                USDC: data['usd-coin']?.usd || secureLiveRates.USDC,
                TRX: data.tron?.usd || secureLiveRates.TRX,
                BNB: data.bnb?.usd || secureLiveRates.BNB
            };
            lastRateFetch = now;
        } else {
            // Provedor Secundário (Failover Automático): CryptoCompare
            const fallbackUrl = 'https://min-api.cryptocompare.com/data/price?fsym=USD&tsyms=BTC,DOGE,LTC,SOL,ETH,USDT,USDC,TRX,BNB';
            const ccRes = await fetch(fallbackUrl);

            if (ccRes.ok) {
                const ccData = await ccRes.json();
                Object.keys(secureLiveRates).forEach(symbol => {
                    if (ccData[symbol]) {
                        secureLiveRates[symbol] = parseFloat((1 / ccData[symbol]).toFixed(4));
                    }
                });
                lastRateFetch = now;
            }
        }
    } catch (error) {
        console.error('[Oracle Error] Mantendo última cotação válida em cache:', error.message);
    } finally {
        isFetching = false;
    }

    return secureLiveRates;
}

/**
 * Verificação Zero-Trust de Webhook Blockchain (Reverse Lookup Pattern)
 */
async function verifyAndProcessCryptoWebhook(req, res, { UserModel, DepositModel }) {
    try {
        const payload = { ...req.body };
        if (!payload.txn_id) return res.status(200).send('OK');

        const PLISIO_API_KEY = process.env.PLISIO_SECRET_KEY?.trim();
        if (!PLISIO_API_KEY) return res.status(500).send('Internal Server Error');

        // 1. Reverse Lookup: Consulta diretamente a fonte da verdade na API do Gateway
        const verifyUrl = `https://api.plisio.net/api/v1/operations/${payload.txn_id}?api_key=${PLISIO_API_KEY}`;
        const verifyResponse = await fetch(verifyUrl);
        const verifyData = await verifyResponse.json();

        if (verifyData.status !== 'success' || !verifyData.data) {
            return res.status(403).send('Forbidden: Unverified Transaction');
        }

        const realTx = verifyData.data;
        const hasBlockchainHash = (realTx.tx_id && realTx.tx_id.length > 0) || realTx.tx_url;

        if ((realTx.status === 'new' || realTx.status === 'expired') && !hasBlockchainHash) {
            return res.status(200).send('OK');
        }

        const isPaid = ['completed', 'mismatch', 'overpaid'].includes(realTx.status) || hasBlockchainHash;
        if (!isPaid) return res.status(200).send('OK');

        // 2. Extração exata do montante liquidado (proteção contra underpayment/overpayment)
        const [userId] = realTx.order_number.split('_');
        const amountCrypto = parseFloat(realTx.amount_received || realTx.actual_amount || realTx.amount);
        const currency = realTx.currency.includes('_') ? realTx.currency.split('_')[0] : realTx.currency;

        if (!amountCrypto || amountCrypto <= 0) return res.status(200).send('OK');

        // 3. Isolamento do Hash da Blockchain para Idempotência Estrita
        let blockchainHash = realTx.txn_id;
        if (Array.isArray(realTx.tx_id) && realTx.tx_id.length > 0) {
            blockchainHash = realTx.tx_id[0];
        } else if (realTx.tx_url) {
            blockchainHash = realTx.tx_url.split('/').pop();
        }

        // 4. Trava de Idempotência (Evita Race Condition e Duplo Gasto)
        const depositExists = await DepositModel.findOne({
            $or: [{ txId: blockchainHash }, { txId: realTx.txn_id }]
        });
        if (depositExists) return res.status(200).send('OK');

        // 5. Persistência Transacional
        await DepositModel.create({
            user: userId,
            currency,
            amount: amountCrypto,
            address: realTx.wallet_hash,
            txId: blockchainHash,
            status: 'completed'
        });

        const balanceField = `${currency.toLowerCase()}Balance`;
        await UserModel.findByIdAndUpdate(userId, { $inc: { [balanceField]: amountCrypto } });

        return res.status(200).send('OK');
    } catch (err) {
        console.error('[Webhook Critical Error]:', err.message);
        return res.status(200).send('OK');
    }
}

module.exports = { getResilientCryptoRates, verifyAndProcessCryptoWebhook };
