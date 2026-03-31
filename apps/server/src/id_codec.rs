use uuid::Uuid;

pub fn uuid_to_db(id: Uuid) -> String {
    id.to_string()
}

pub fn uuid_from_db(raw: &str) -> Result<Uuid, uuid::Error> {
    Uuid::parse_str(raw)
}
