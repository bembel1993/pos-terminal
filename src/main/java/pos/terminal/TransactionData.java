package pos.terminal;

public class TransactionData {
	private String cardNumber;
    private int amount;
    private String transId;
    private int merchantId;

    public TransactionData(String cardNumber, int amount, String transId, int merchantId) {
        this.cardNumber = cardNumber;
        this.amount = amount;
        this.transId = transId;
        this.merchantId = merchantId;
    }

    public String getCardNumber() { return cardNumber; }
    public int getAmount() { return amount; }
    public String getTransId() { return transId; }
    public int getMerchantId() { return merchantId; }
}
