use lwk_common::Network;

#[must_use]
pub fn to_lwk_wollet_network(network: Network) -> lwk_wollet::ElementsNetwork {
    match network {
        Network::Liquid => lwk_wollet::ElementsNetwork::Liquid,
        Network::TestnetLiquid => lwk_wollet::ElementsNetwork::LiquidTestnet,
        Network::LocaltestLiquid => lwk_wollet::ElementsNetwork::default_regtest(),
    }
}