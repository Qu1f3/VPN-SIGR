class SequenceManager:

    def __init__(self):
        self.send_sequence = 0
        self.receive_sequence = 0


    def next_send(self):
        sequence = self.send_sequence
        self.send_sequence += 1

        return sequence


    def validate_receive(self, sequence):
        if sequence < self.receive_sequence:
            return False

        self.receive_sequence = sequence + 1

        return True